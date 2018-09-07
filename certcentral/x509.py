"""
Module containing x509 helper classes

Valentin Gutierrez <vgutierrez@wikimedia.org> 2018
"""
import abc
import hashlib
import ipaddress
import os
import stat
from datetime import datetime, timedelta
from enum import Enum

from cryptography import x509 as crypto_x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID, NameOID

CRYPTOGRAPHY_BACKEND = default_backend()
DEFAULT_RSA_KEY_SIZE = 2048
DEFAULT_RSA_PUBLIC_EXPONENT = 65537
DEFAULT_SIGNATURE_ALGORITHM = hashes.SHA256()
DEFAULT_EC_CURVE = ec.SECP256R1  # pylint: disable=invalid-name
DEFAULT_RENEWAL_PERIOD = timedelta(days=30)
OPENER_MODE = 0o640
PEM_HEADER_AND_FOOTER_LEN = 52


class X509Error(Exception):
    """Base exception class for the X509 module"""


class CertificateSaveMode(Enum):
    """
    Certificate save modes.
    To be used in Certificate.save()
    """
    CERT_ONLY = 1
    CHAIN_ONLY = 2
    FULL_CHAIN = 3  # certificate + chain


class CertificateRevokeReason(Enum):
    """
    Certificate revoke reason codes as defined in
    RFC 5280 5.3.1
    """
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    REMOVE_FROM_CRL = 8
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10


def secure_opener(path, flags):
    """
    custom opener to be used with open(file, mode, opener=secure_opener).
    Ensures that newly created files are created with OPENER_MODE permissions
    """
    return os.open(path, flags, OPENER_MODE)


class PrivateKeyLoader(object):
    """PrivateKey factory that reads an existing key from disk"""
    @staticmethod
    def load(filename):
        """
        Loads a private key from disk after checking that permissions
        only allow access to the owner of the file
        """
        key_stat = os.stat(filename)
        if key_stat.st_mode & (stat.S_IWGRP | stat.S_IXGRP | stat.S_IRWXO):
            raise X509Error("permissions ({:o}) are too open for {}".format(stat.S_IMODE(key_stat.st_mode), filename))

        with open(filename, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=CRYPTOGRAPHY_BACKEND,
            )
            if isinstance(private_key, rsa.RSAPrivateKey):
                return RSAPrivateKey(private_key=private_key)
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                return ECPrivateKey(private_key=private_key)
            else:
                raise NotImplementedError("Unsupported private key type")


class PrivateKey(abc.ABC):
    """
    Base class that handles PrivateKeys. It already implements:
        - save()
    And subclasses are required to implement:
        - generate(self, **kwargs)
    """
    def __init__(self, private_key=None):
        self.key = private_key

    @abc.abstractmethod
    def generate(self, **kwargs):
        """Generates a new private key"""

    @property
    def public_pem(self):
        """Returns the PEM of the public key"""
        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def save(self, filename):
        """Persists the private key on disk"""
        with open(filename, 'wb', opener=secure_opener) as key_file:
            key_file.write(self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))


class RSAPrivateKey(PrivateKey):
    """RSA Private Key implementation"""
    def generate(self, **kwargs):
        """
        Generates a new RSA private key
        Supported parameters:
            - size <int> default value: DEFAULT_RSA_KEY_SIZE
        """
        size = kwargs.get('size', DEFAULT_RSA_KEY_SIZE)

        self.key = rsa.generate_private_key(
            public_exponent=DEFAULT_RSA_PUBLIC_EXPONENT,
            key_size=size,
            backend=CRYPTOGRAPHY_BACKEND,
        )


class ECPrivateKey(PrivateKey):
    """Elliptic Curve Private Key implementation"""
    def generate(self, **kwargs):
        """
        Generates a new elliptic curve private key
        Supported parameters
            - curve <instance of cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve>
              default value: DEFAULT_EC_CURVE
        """
        curve = kwargs.get('curve', DEFAULT_EC_CURVE)

        self.key = ec.generate_private_key(
            curve=curve,
            backend=CRYPTOGRAPHY_BACKEND,
        )


class BaseX509Builder(object):
    """
    Base class for CSR and SelfSignedCertificate classes. It centralizes common stuff:
        - common name
        - SANs
        - sign() and save() methods
    """
    def __init__(self, builder, private_key, common_name, sans):
        if not isinstance(private_key, PrivateKey):
            raise TypeError("private_key must be either a RSAPrivateKey or ECPrivateKey instance")
        if not isinstance(sans, (list, tuple)):
            raise TypeError("SANs must be a tuple or a list")

        self.private_key = private_key
        self.common_name = crypto_x509.Name([
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        self._builder = builder.subject_name(self.common_name)

        self.append_sans(sans)

    def append_sans(self, sans):
        """
        Adds the SubjectAlternativeNames with the following rules:
            - strings are added as DNS Names
            - IPv(4|6)Address instances are added as IPAddress Names
        """
        x509_names = []
        for san in sans:
            if isinstance(san, str):
                x509_names.append(crypto_x509.DNSName(san))
            elif isinstance(san, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                x509_names.append(crypto_x509.IPAddress(san))
        if x509_names:
            self._builder = self._builder.add_extension(crypto_x509.SubjectAlternativeName(x509_names),
                                                        critical=False)

    def save(self, filename):
        """Persists the x509 document on disk after being signed"""
        with open(filename, 'wb', opener=secure_opener) as pem_file:
            pem_file.write(self.pem)

    def sign(self):
        """Signs the element being built with self.private_key using the DEFAULT_SIGNATURE algorithm"""
        return self._builder.sign(
            private_key=self.private_key.key,
            algorithm=DEFAULT_SIGNATURE_ALGORITHM,
            backend=CRYPTOGRAPHY_BACKEND,
        )

    @property
    def pem(self):
        """Returns the X.509 object serialized as a PEM"""
        return self.sign().public_bytes(encoding=serialization.Encoding.PEM)


class CertificateSigningRequest(BaseX509Builder):
    """Certificate Signing Request (CSR) generator"""
    def __init__(self, private_key, common_name, sans):
        super().__init__(crypto_x509.CertificateSigningRequestBuilder(), private_key, common_name, sans)
        self.wildcard = self._find_wildcard()
        self.csr_id = CertificateSigningRequest.generate_csr_id(private_key.public_pem, common_name, sans)

    @property
    def request(self):
        """Signed CSR"""
        return self.sign()

    def _find_wildcard(self):
        """Returns true if a wildcard SAN is found, false otherwise"""
        try:
            sans = self.request.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        except ExtensionNotFound:
            return False

        dns_names = sans.value.get_values_for_type(crypto_x509.DNSName)
        for dns_name in dns_names:
            if dns_name.startswith('*.'):
                return True
        return False

    @staticmethod
    def generate_csr_id(public_key_pem, common_name, sans):
        """Generates the CSR id built with the following parameters:
            - PEM of the public key used to sign the CSR
            - common name in the CSR
            - SANS in the CSR
        """
        csr_id = hashlib.md5()
        csr_id.update(public_key_pem)
        csr_id.update(common_name.lower().encode('utf-8'))
        for san in sans:
            csr_id.update(str(san).lower().encode('utf-8'))

        return csr_id.hexdigest()


class SelfSignedCertificate(BaseX509Builder):
    """Self Signed Certificate generator"""
    def __init__(self, private_key, common_name, sans, from_date, until_date):
        super().__init__(crypto_x509.CertificateBuilder(), private_key, common_name, sans)

        if not (isinstance(from_date, datetime) and isinstance(until_date, datetime)):
            raise TypeError("from_date/until_date parameters must be datetime.datetime instances")

        self._builder = self._builder.issuer_name(self.common_name)
        self._builder = self._builder.public_key(self.private_key.key.public_key())
        self._builder = self._builder.serial_number(crypto_x509.random_serial_number())
        self._builder = self._builder.not_valid_before(from_date)
        self._builder = self._builder.not_valid_after(until_date)

    @property
    def certificate(self):
        """self signed certificate"""
        return self.sign()


class Certificate:
    """X.509 certificate"""
    def __init__(self, pem, parse_chain=True):
        try:
            self.certificate = crypto_x509.load_pem_x509_certificate(pem, CRYPTOGRAPHY_BACKEND)
        except (TypeError, ValueError) as load_pem_error:
            raise X509Error('Unable to parse PEM') from load_pem_error

        self.chain = [self]
        if parse_chain:
            self._parse_chain_pem(pem[len(self.pem):].lstrip())

    def _parse_chain_pem(self, pem):
        len_pem = len(pem)
        if len_pem <= PEM_HEADER_AND_FOOTER_LEN:
            return

        self.chain.append(Certificate(pem, parse_chain=False))
        len_last_pem = len(self.chain[-1].pem)
        if len_pem - len_last_pem > PEM_HEADER_AND_FOOTER_LEN:
            self._parse_chain_pem(pem[len_last_pem:].lstrip())

    @staticmethod
    def load(path):
        """Loads the certificate from a PEM on disk"""
        with open(path, 'rb') as pem_file:
            return Certificate(pem_file.read())

    @property
    def pem(self):
        """Returns the certificate serialized as a PEM"""
        return self.certificate.public_bytes(encoding=serialization.Encoding.PEM)

    @property
    def self_signed(self):
        """Returns True if the certificate is self signed, False otherwise"""
        return self.certificate.issuer == self.certificate.subject

    def save(self, path, mode=CertificateSaveMode.CERT_ONLY):
        """Persists the certificate on disk serializad as a PEM"""
        if mode is CertificateSaveMode.CERT_ONLY:
            save_chain = self.chain[0:1]
        elif mode is CertificateSaveMode.CHAIN_ONLY:
            save_chain = self.chain[1:]
        else:
            save_chain = self.chain

        with open(path, 'wb') as pem_file:
            for cert in save_chain:
                pem_file.write(cert.pem)

    def needs_renew(self, renewal_period=DEFAULT_RENEWAL_PERIOD):
        """Returns True if the certificate needs to be renewed"""
        now = datetime.utcnow()
        if renewal_period > (self.certificate.not_valid_after - now):
            return True

        return False
