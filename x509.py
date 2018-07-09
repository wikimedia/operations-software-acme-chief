"""
Module containing x509 helper classes

Valentin Gutierrez <vgutierrez@wikimedia.org> 2018
"""
import abc
import ipaddress
import os
import stat
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

CRYPTOGRAPHY_BACKEND = default_backend()
DEFAULT_RSA_KEY_SIZE = 2048
DEFAULT_RSA_PUBLIC_EXPONENT = 65537
DEFAULT_SIGNATURE_ALGORITHM = hashes.SHA256()
DEFAULT_EC_CURVE = ec.SECP256R1  # pylint: disable=invalid-name
OPENER_MODE = 0o600


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
        if key_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise Exception("permissions ({:o}) are too open for {}".format(stat.S_IMODE(key_stat.st_mode), filename))

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
        self.common_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
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
                x509_names.append(x509.DNSName(san))
            elif isinstance(san, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                x509_names.append(x509.IPAddress(san))
        if x509_names:
            self._builder = self._builder.add_extension(x509.SubjectAlternativeName(x509_names), critical=False)

    def save(self, filename):
        """Persists the x509 document on disk after being signed"""
        with open(filename, 'wb', opener=secure_opener) as pem_file:
            pem_file.write(self.sign().public_bytes(encoding=serialization.Encoding.PEM))

    def sign(self):
        """Signs the element being built with self.private_key using the DEFAULT_SIGNATURE algorithm"""
        return self._builder.sign(
            private_key=self.private_key.key,
            algorithm=DEFAULT_SIGNATURE_ALGORITHM,
            backend=CRYPTOGRAPHY_BACKEND,
        )


class CertificateSigningRequest(BaseX509Builder):
    """Certificate Signing Request (CSR) generator"""
    def __init__(self, private_key, common_name, sans):
        super().__init__(x509.CertificateSigningRequestBuilder(), private_key, common_name, sans)

    @property
    def request(self):
        """Signed CSR"""
        return self.sign()


class SelfSignedCertificate(BaseX509Builder):
    """Self Signed Certificate generator"""
    def __init__(self, private_key, common_name, sans, from_date, until_date):
        super().__init__(x509.CertificateBuilder(), private_key, common_name, sans)

        if not (isinstance(from_date, datetime) and isinstance(until_date, datetime)):
            raise TypeError("from_date/until_date parameters must be datetime.datetime instances")

        self._builder = self._builder.issuer_name(self.common_name)
        self._builder = self._builder.public_key(self.private_key.key.public_key())
        self._builder = self._builder.serial_number(x509.random_serial_number())
        self._builder = self._builder.not_valid_before(from_date)
        self._builder = self._builder.not_valid_after(until_date)

    @property
    def certificate(self):
        """self signed certificate"""
        return self.sign()
