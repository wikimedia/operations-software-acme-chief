"""
Module containing ACMEv2 client classes

Valentin Gutierrez <vgutierrez@wikimedia.org> 2018
Wikimedia Foundation 2018
"""
import abc
import hashlib
import logging
import os
import socket
from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum
from urllib.parse import urlunparse

import dns.exception
import dns.resolver
import josepy as jose
import OpenSSL
import requests
from acme import client, errors, messages

# TODO: move secure_opener out of x509
from certcentral.x509 import (Certificate, CertificateRevokeReason,
                              CertificateSigningRequest, PrivateKeyLoader,
                              RSAPrivateKey, X509Error, secure_opener)

BASEPATH = '/etc/certcentral/accounts'
DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'
TLS_VERIFY = True   # intended to be used during testing
DNS_PORT = 53       # intended to be used during testing
DNS_SERVERS = None  # intended to be used during testing
HTTP_VALIDATOR_PROXIES = {
    'http': os.getenv('HTTP_PROXY'),
    'https': os.getenv('HTTPS_PROXY'),
}
DEFAULT_DNS01_VALIDATION_TIMEOUT = 2.0
DEFAULT_HTTP01_VALIDATION_TIMEOUT = 2.0

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class ACMEError(Exception):
    """Base error class"""


class ACMEOrderNotFound(ACMEError):
    """Order not found in the current ACME session"""


class ACMEInvalidChallengeError(ACMEError):
    """Challenge(s) have been marked as INVALID"""


class ACMEChallengeNotValidatedError(ACMEError):
    """Challenge(s) have not been validated yet by the ACME Directory"""


class ACMEAccountFiles(Enum):
    """Files needed to persist an account"""
    KEY = 'private_key.pem'
    REGR = 'regr.json'


class ACMEChallengeType(Enum):
    """ACMEv2 challenge types"""
    DNS01 = 'dns-01'
    HTTP01 = 'http-01'


class ACMEChallengeValidation(Enum):
    """Possible results of challenge validation"""
    VALID = 1
    INVALID = 2
    UNKNOWN = 3


class BaseACMEChallenge(abc.ABC):
    """Base ACME challenges class"""
    def __init__(self, challenge_type, validation):
        self.challenge_type = challenge_type
        self.validation = validation

    def save(self, file_name):
        """Persists the challenge on disk"""
        with open(file_name, 'w') as challenge_file:
            challenge_file.write(self.validation)

    @abc.abstractmethod
    def validate(self, **kwargs):
        """Checks if the challenge has been fulfilled or not. Returns a member of ACMEChallengeValidation"""

    def __str__(self):
        return "Challenge type: {}".format(self.challenge_type)


class DNS01ACMEChallenge(BaseACMEChallenge):
    """Class representing dns-01 challenge"""
    def __init__(self, validation_domain_name, validation):
        super().__init__(ACMEChallengeType.DNS01, validation)
        self.validation_domain_name = validation_domain_name
        self.file_name = "{}-{}".format(validation_domain_name, validation)

    @staticmethod
    def _resolve_dns_servers(dns_servers):
        """Use system resolver to attempt to resolve DNS servers specified as hostnames"""
        ret = []
        for dns_server in dns_servers:
            addresses_info = socket.getaddrinfo(dns_server, 53, proto=socket.IPPROTO_UDP)
            for _, _, _, _, sockaddr in addresses_info:
                ret.append(sockaddr[0])

        return ret

    def validate(self, **kwargs):
        logger.debug("Attempting to validate challenge %s", self)
        resolver = dns.resolver.Resolver()
        resolver.port = DNS_PORT
        dns_servers = kwargs.get('dns_servers', DNS_SERVERS)
        if dns_servers is not None:
            try:
                resolver.nameservers = self._resolve_dns_servers(dns_servers)
            except OSError:
                logger.exception("Unable to resolve configured dns servers %s. Using system DNS servers as fallback",
                                 dns_servers)

        resolver.timeout = kwargs.get('timeout', DEFAULT_DNS01_VALIDATION_TIMEOUT)
        resolver.lifetime = kwargs.get('timeout', DEFAULT_DNS01_VALIDATION_TIMEOUT)

        try:
            answer = resolver.query(self.validation_domain_name, rdtype='TXT')
        except (dns.resolver.NXDOMAIN, dns.resolver.YXDOMAIN, dns.resolver.NoAnswer):
            return ACMEChallengeValidation.INVALID
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            return ACMEChallengeValidation.UNKNOWN

        for rrset in answer.rrset:
            txt_data = rrset.to_text().strip('"')
            if txt_data == self.validation:
                return ACMEChallengeValidation.VALID

        return ACMEChallengeValidation.INVALID

    def __str__(self):
        return '{}. {} TXT {}'.format(super().__str__(), self.validation_domain_name, self.validation)


class HTTP01ACMEChallenge(BaseACMEChallenge):
    """Class representing http-01 challenge"""
    def __init__(self, hostname, path, validation):
        super().__init__(ACMEChallengeType.HTTP01, validation)
        self.hostname = hostname
        self.path = path
        self.file_name = path.split('/')[-1]

    def validate(self, **kwargs):
        logger.debug("Attempting to validate challenge %s", self)
        timeout = kwargs.get('timeout', DEFAULT_HTTP01_VALIDATION_TIMEOUT)
        server = kwargs.get('server', self.hostname)
        port = kwargs.get('port', 80)

        headers = {'Host': self.hostname}
        url = urlunparse((
            'http',
            "{}:{}".format(server, port),
            self.path,
            '',
            '',
            ''))
        try:
            response = requests.get(url, headers=headers, proxies=HTTP_VALIDATOR_PROXIES, timeout=timeout)
            response.raise_for_status()
        except requests.exceptions.Timeout:
            return ACMEChallengeValidation.UNKNOWN
        except (requests.exceptions.HTTPError, requests.exceptions.TooManyRedirects):
            return ACMEChallengeValidation.INVALID

        if response.text == self.validation:
            return ACMEChallengeValidation.VALID

        return ACMEChallengeValidation.INVALID

    def __str__(self):
        return '{}. http://{}{}: {}'.format(super().__str__(), self.hostname, self.path, self.validation)


class ACMEAccount:
    """"ACMEv2 account management
    heavily based on https://github.com/certbot/certbot/blob/master/certbot/account.py
    """
    def __init__(self, *, key=None, regr=None, base_path=BASEPATH, directory_url=DIRECTORY_URL):
        self.base_path = base_path
        self.directory_url = directory_url
        if key is not None:
            self.key = key
        else:
            self.key = RSAPrivateKey()
            self.key.generate()
        self.regr = regr
        self.account_id = hashlib.md5(self.key.public_pem).hexdigest()

    @staticmethod
    def _get_acme_client(jkey, regr=None, directory_url=DIRECTORY_URL):
        net = client.ClientNetwork(key=jkey, account=regr, verify_ssl=TLS_VERIFY)
        try:
            directory = messages.Directory.from_json(net.get(directory_url).json())
        except (errors.Error, ValueError) as dir_error:
            raise ACMEError('Unable to fetch directory URLs') from dir_error

        return client.ClientV2(directory, net)

    @staticmethod
    def _get_paths(account_id, base_path=BASEPATH, create_directory=False):
        directory_name = os.path.join(base_path, account_id)
        if create_directory:
            os.makedirs(directory_name, mode=0o700, exist_ok=True)

        return {account_file: os.path.join(directory_name, account_file.value) for account_file in ACMEAccountFiles}

    @property
    def client(self):
        """Return an acme.client.ClientV2 for the current ACMEAccount"""
        return self._get_acme_client(self.jkey, self.regr, directory_url=self.directory_url)

    @property
    def jkey(self):
        """Return a JOSE JWKRSA instance of the account key"""
        return jose.JWKRSA(key=self.key.key)

    @classmethod
    def create(cls, email, base_path=BASEPATH, directory_url=DIRECTORY_URL):
        """Creates a new ACME Account using the specified email as point of contact"""
        ret = ACMEAccount(base_path=base_path, directory_url=directory_url)
        new_reg = messages.NewRegistration.from_data(email=email,
                                                     terms_of_service_agreed=True)
        acme = cls._get_acme_client(ret.jkey, directory_url=directory_url)
        try:
            regr = acme.new_account(new_reg)
        except errors.Error as account_error:
            raise ACMEError('Unable to create ACME account') from account_error

        ret.regr = messages.RegistrationResource(body={}, uri=regr.uri)

        return ret

    @classmethod
    def load(cls, account_id, base_path=BASEPATH, directory_url=DIRECTORY_URL):
        """Load the account with the specified account_id from disk"""
        logger.debug("Loading ACME account %s from directory: %s", account_id, directory_url)
        paths = ACMEAccount._get_paths(account_id, base_path=base_path)

        key = PrivateKeyLoader.load(paths[ACMEAccountFiles.KEY])
        with open(paths[ACMEAccountFiles.REGR], 'r') as regr_file:
            regr = messages.RegistrationResource.json_loads(regr_file.read())

        return ACMEAccount(key=key, regr=regr, base_path=base_path, directory_url=directory_url)

    def save(self):
        """Stores the account on disk to be used in the future"""
        paths = ACMEAccount._get_paths(self.account_id, base_path=self.base_path, create_directory=True)
        self.key.save(paths[ACMEAccountFiles.KEY])
        with open(paths[ACMEAccountFiles.REGR], 'w', opener=secure_opener) as regr_file:
            regr_file.write(self.regr.json_dumps())


class ACMERequests:
    """ACMERequests provides high level methods for the following operations:
        - Request a new certificate
        - Renew an existing certificate
    """
    def __init__(self, acme_account):
        self.acme_account = acme_account
        self.acme_client = acme_account.client
        self.challenges = {}
        self.orders = {}

        if not self._account_is_valid():
            raise ACMEError('ACME account marked as not valid')

    def _clean(self, csr_id):
        if csr_id in self.orders:
            del self.orders[csr_id]

        if csr_id in self.challenges:
            del self.challenges[csr_id]

    def _account_is_valid(self):
        try:
            regr = self.acme_client.update_registration(self.acme_account.regr)
        except errors.Error as update_error:
            raise ACMEError('Unable to verify ACME account status') from update_error

        return regr.body.status == 'valid'

    def _get_challenges_from_order(self, order, wildcard):
        """Returns the suitable challenges for the specified order. If the order
        includes wildcard SANs, http-01 challenges will be discarded
        Parameters:
          - order: acme.messages.OrderResource instance
          - wildcard: bool signaling if the order includes a wildcard SAN or not
        """
        challenges = defaultdict(list)

        for auth in order.authorizations:
            for challenge in auth.body.challenges:
                if challenge.typ == ACMEChallengeType.DNS01.value:
                    challenges[ACMEChallengeType.DNS01].append(DNS01ACMEChallenge(
                        validation_domain_name=challenge.validation_domain_name(auth.body.identifier.value),
                        validation=challenge.validation(self.acme_account.jkey),
                    ))
                elif challenge.typ == ACMEChallengeType.HTTP01.value and not wildcard:
                    challenges[ACMEChallengeType.HTTP01].append(HTTP01ACMEChallenge(
                        hostname=auth.body.identifier.value,
                        path=challenge.path,
                        validation=challenge.validation(self.acme_account.jkey),
                    ))

        return challenges

    def _get_order(self, csr_id):
        try:
            return self.orders[csr_id]
        except KeyError:
            raise ACMEOrderNotFound('csr_id {} not found'.format(csr_id))

    def push_csr(self, csr):
        """
        Sends the CSR to the ACMEv2 server.
        Returns a list of ACMEChallenges to be fulfilled.
        If a wilcard SAN is present, only dns-01 challenges will be returned,
        because it's the only challenge available to provide proof for wilcards.
        """

        if not isinstance(csr, CertificateSigningRequest):
            raise TypeError("csr must be a CertificateSigningRequest instance, got: {}".format(type(csr)))

        try:
            new_order = self.acme_client.new_order(csr.pem)
        except errors.Error as order_error:
            raise ACMEError('Unable to push CSR') from order_error

        self.orders[csr.csr_id] = new_order

        self.challenges[csr.csr_id] = self._get_challenges_from_order(new_order, csr.wildcard)

        return self.challenges[csr.csr_id]

    def push_solved_challenges(self, csr_id, challenge_type=ACMEChallengeType.DNS01):
        """
        Sends back to the ACME directory the solution for the challenges
        of the type specified in challeng_typ. Defaults to dns-01 because
        it's the only one that can validate any kind of certificate
        (including wildcard certificates)
        """

        order = self._get_order(csr_id)

        for auth in order.authorizations:
            for challenge in auth.body.challenges:
                if challenge.typ != challenge_type.value:
                    continue
                response = challenge.response(self.acme_account.jkey)
                try:
                    self.acme_client.answer_challenge(challenge, response)
                except errors.Error as answer_challenge_error:
                    raise ACMEError('Unable to answer challenge') from answer_challenge_error

    def get_certificate(self, csr_id, deadline=None):
        """
        Returns the certificate and the full chain (if present) wrapped in
        a x509.Certificate instance.
        This should be called after the challenges have been fulfilled.
        """
        if deadline is None:
            # using now() instead of utcnow() cause acme_client uses now()
            # and using utcnow() on systems where now() != utcnow() cause
            # unexpected behaviour
            deadline = datetime.now() + timedelta(seconds=2)

        order = self._get_order(csr_id)
        try:
            finished_order = self.acme_client.poll_and_finalize(order, deadline=deadline)
        except errors.TimeoutError:
            # TimeoutError is raised if the challenges have not been validated yet
            raise ACMEChallengeNotValidatedError('ACME directory has not been able to validate the challenge(s) yet')
        except errors.ValidationError:
            self._clean(csr_id)
            raise ACMEInvalidChallengeError('Unable to get certificate')
        except errors.Error as finalize_error:
            self._clean(csr_id)
            raise ACMEError('Unable to get certificate') from finalize_error

        try:
            certificate = Certificate(finished_order.fullchain_pem.encode('utf-8'))
        except X509Error as certificate_error:
            raise ACMEError('Received invalid PEM from ACME server') from certificate_error

        self._clean(csr_id)
        return certificate

    def revoke_certificate(self, certificate, reason=CertificateRevokeReason.UNSPECIFIED):
        """Revoke the specified certificate"""
        try:
            openssl_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate.pem)
        except OpenSSL.crypto.Error as openssl_error:
            raise ACMEError('Unable to get an OpenSSL X509 object from the specified certificate') from openssl_error

        try:
            self.acme_client.revoke(jose.ComparableX509(openssl_cert), reason.value)
        except errors.Error as revoke_error:
            raise ACMEError('Unable to revoke certificate') from revoke_error
