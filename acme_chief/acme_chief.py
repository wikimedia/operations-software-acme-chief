# Central certificates service
# Alex Monk <krenair@gmail.com>, May/June 2018
# Valentin Gutierrez <vgutierrez@wikimedia.org> Wikimedia Foundation. 2018

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
This module is the main source code behind Wikimedia's central certificates service.
A description of it can be found at https://phabricator.wikimedia.org/T194962
"""
import argparse
import collections
import copy
import datetime
import logging
import logging.config
import os
import pathlib
import signal
import subprocess
import uuid
from enum import Enum
from time import sleep

from cryptography.hazmat.primitives.asymmetric import ec

from acme_chief.acme_requests import (ACMEAccount,
                                      ACMEChallengeNotValidatedError,
                                      ACMEChallengeType,
                                      ACMEChallengeValidation, ACMEError,
                                      ACMEInvalidChallengeError,
                                      ACMEIssuedCertificateError,
                                      ACMEOrderNotFound, ACMERequests,
                                      ACMETimeoutFetchingCertificateError,
                                      DNS01ACMEValidator, HTTP01ACMEValidator)
from acme_chief.config import ACMEChiefConfig
from acme_chief.ocsp import OCSPRequest, OCSPRequestError, OCSPResponse, OCSPResponseError
from acme_chief.x509 import (Certificate, CertificateSaveMode,
                             CertificateSigningRequest, ECPrivateKey,
                             PrivateKeyLoader, RSAPrivateKey,
                             SelfSignedCertificate, X509Error)

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

PATHS = {
    'config': '/etc/acme-chief',
    'certificates': '/var/lib/acme-chief',
}
KEY_TYPES = {
    'ec-prime256v1': {
        'class': ECPrivateKey,
        'params': {
            'curve': ec.SECP256R1,
        }
    },
    'rsa-2048': {
        'class': RSAPrivateKey,
        'params': {
            'size': 2048,
        }
    }
}

LOGGING_CONFIG = {
    'disable_existing_loggers': False,
    'version': 1,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',  # logging handler that outputs log messages to terminal
            'level': 'INFO',                   # message level to be written to console
        },
    },
    'loggers': {
        'acme_chief': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'acme_requests': {
            'handlers': ['console'],
            'level': 'INFO',
        },
    }
}

# naming schema borrowed from
# https://phabricator.wikimedia.org/source/operations-puppet/browse/production/modules/letsencrypt/manifests/cert/integrated.pp
CERTIFICATE_TYPES = {
    'cert_only': {
        'save_mode': CertificateSaveMode.CERT_ONLY,
        'file_name': '{key_type_id}.crt',
        'embedded_key': False,
        'alternative_chain': False,
    },
    'cert_key': {
        'save_mode': CertificateSaveMode.CERT_ONLY,
        'file_name': '{key_type_id}.crt.key',
        'embedded_key': True,
        'alternative_chain': False,
    },
    'chain_only': {
        'save_mode': CertificateSaveMode.CHAIN_ONLY,
        'file_name': '{key_type_id}.chain.crt',
        'embedded_key': False,
        'alternative_chain': False,
    },
    'full_chain': {
        'save_mode': CertificateSaveMode.FULL_CHAIN,
        'file_name': '{key_type_id}.chained.crt',
        'embedded_key': False,
        'alternative_chain': False,
    },
    'full_chain_key': {
        'save_mode': CertificateSaveMode.FULL_CHAIN,
        'file_name': '{key_type_id}.chained.crt.key',
        'embedded_key': True,
        'alternative_chain': False,
    },
    'alt_chain_only': {
        'save_mode': CertificateSaveMode.CHAIN_ONLY,
        'file_name': '{key_type_id}.alt.chain.crt',
        'embedded_key': False,
        'alternative_chain': True,
    },
    'full_alt_chain': {
        'save_mode': CertificateSaveMode.FULL_CHAIN,
        'file_name': '{key_type_id}.alt.chained.crt',
        'embedded_key': False,
        'alternative_chain': True,
    },
    'full_alt_chain_key': {
        'save_mode': CertificateSaveMode.FULL_CHAIN,
        'file_name': '{key_type_id}.alt.chained.crt.key',
        'embedded_key': True,
        'alternative_chain': True,
    }
}

CHALLENGE_TYPES = {
    'dns-01': ACMEChallengeType.DNS01,
    'http-01': ACMEChallengeType.HTTP01,
}


class CertificateStatus(Enum):
    """Certificate status definition"""
    INITIAL = 1
    SELF_SIGNED = 2           # initial self-signed certificate issued to let services start
    CSR_PUSHED = 3            # CSR pushed to the ACME directory and challenges saved on disk
    PREVALIDATION_FAILED = 4  # Prevalidation failed. The configured certificate cannot be issued
    CHALLENGES_VALIDATED = 5  # Challenges have been successfully validated
    CHALLENGES_PUSHED = 6     # Challenges pushed to the ACME directory
    CHALLENGES_REJECTED = 7   # Challenges have been rejected by the ACME directory
    ORDER_FINALIZED = 8       # Order finalization request sent to the ACME directory
    CERTIFICATE_ISSUED = 9    # Certificate issued by the ACME directory but still not persisted on disk
    VALID = 10                # Valid certificate succesfully persisted on disk
    NEEDS_RENEWAL = 11        # Valid certificate that needs to be renew soon!
    CERTIFICATE_STAGED = 12   # Certificate issued and blocked by staging_time
    READY_TO_BE_PUSHED = 13   # New certificate issued and waiting to be pushed to ACMEChief.live_certs_path
    EXPIRED = 14              # Expired certificate
    SUBJECTS_CHANGED = 15     # Configuration of cert (CN/SANs) has changed, need to re-issue
    ACMECHIEF_ERROR = 16      # Certificate issuance failed due to some ACMEChief non-recoverable error
    ACMEDIR_ERROR = 17        # Certificate issuance failed due to some ACME directory non-recoverable error


class CertificateState:
    """
    CertificateState tracks the current status of a certificate and the number of retries performed to
    reach CertificateStatus.VALID status. After MAX_CONSECUTIVE_RETRIES it will apply an exponential backoff to the
    status listed in STATUS_WITH_RETRIES and it will impose a slow retry policy (+1day) for status listed in
    STATUS_WITH_SLOW_RETRIES
    """
    STATUS_WITH_RETRIES = (CertificateStatus.CSR_PUSHED, CertificateStatus.CHALLENGES_VALIDATED,
                           CertificateStatus.CHALLENGES_PUSHED, CertificateStatus.ACMEDIR_ERROR,
                           CertificateStatus.ORDER_FINALIZED)
    STATUS_WITH_SLOW_RETRIES = (CertificateStatus.CHALLENGES_REJECTED, CertificateStatus.CERTIFICATE_ISSUED,
                                CertificateStatus.ACMECHIEF_ERROR, CertificateStatus.PREVALIDATION_FAILED)
    MAX_CONSECUTIVE_RETRIES = 3
    MAX_RETRIES = 16
    CERTIFICATE_STAGED_RETRY = datetime.timedelta(seconds=3600)
    SLOW_RETRY = datetime.timedelta(days=1)

    def __init__(self, status):
        self._status = status
        self._retries = 0
        self._next_retry = datetime.datetime.fromtimestamp(0)

    @property
    def next_retry(self):
        """When should be performed the next retry. None if retries must be stopped"""
        return self._next_retry

    @property
    def retries(self):
        """Number of retries already attempted without reaching the VALID status"""
        return self._retries

    @property
    def retry(self):
        """True if the retry can be performed. False otherwise"""
        if self._next_retry is not None and datetime.datetime.utcnow() > self._next_retry:
            return True

        return False

    @property
    def status(self):
        """Current status"""
        return self._status

    @status.setter
    def status(self, value):
        self._status = value

        if value in CertificateState.STATUS_WITH_SLOW_RETRIES:
            self._retries += 1
            self._next_retry = datetime.datetime.utcnow() + CertificateState.SLOW_RETRY
            return

        if value not in CertificateState.STATUS_WITH_RETRIES + CertificateState.STATUS_WITH_SLOW_RETRIES:
            self._retries = 0
            if value is CertificateStatus.CERTIFICATE_STAGED:
                self._next_retry = datetime.datetime.utcnow() + CertificateState.CERTIFICATE_STAGED_RETRY
            else:
                self._next_retry = datetime.datetime.fromtimestamp(0)
            return

        self._retries += 1

        if self._retries > CertificateState.MAX_RETRIES:
            self._next_retry = None
        elif self._retries > CertificateState.MAX_CONSECUTIVE_RETRIES:
            self._next_retry = datetime.datetime.utcnow() + datetime.timedelta(seconds=2**self.retries)
        else:
            self._next_retry = datetime.datetime.fromtimestamp(0)


class ACMEChief():
    """
    This class just acts as a container for all the methods and state - config and authorized hosts
    data.
    """
    certs_path = 'certs'
    live_symlink_name = 'live'
    new_symlink_name = 'new'
    accounts_path = 'accounts'
    csrs_path = 'csrs'
    config_path = 'config.yaml'
    confd_path = 'conf.d'
    http_challenges_path = 'http_challenges'
    dns_challenges_path = 'dns_challenges'

    def __init__(self, config_path=PATHS['config'], certificates_path=PATHS['certificates']):
        self._configure_logging()
        self.certs_path = os.path.join(certificates_path, ACMEChief.certs_path)
        self.csrs_path = os.path.join(certificates_path, ACMEChief.csrs_path)
        self.accounts_path = os.path.join(config_path, ACMEChief.accounts_path)
        self.config_path = os.path.join(config_path, ACMEChief.config_path)
        self.confd_path = os.path.join(config_path, ACMEChief.confd_path)
        self.challenges_path = {
            ACMEChallengeType.DNS01: os.path.join(certificates_path, ACMEChief.dns_challenges_path),
            ACMEChallengeType.HTTP01: os.path.join(certificates_path, ACMEChief.http_challenges_path),
        }
        self.config = None
        self.acme_sessions = {}
        self.cert_status = collections.defaultdict(dict)
        signal.signal(signal.SIGHUP, self.sighup_handler)
        self.sighup_handler()

    @staticmethod
    def _configure_logging():
        """Configure logging"""
        logging.config.dictConfig(LOGGING_CONFIG)

    def _create_new_certificate_version(self, cert_id, key_type_id=None):
        if key_type_id is not None:
            # Attempt to load the private key and cert file for key_type_id. Generate a new version if everything
            # goes as expected
            try:
                PrivateKeyLoader.load(self._get_path(cert_id, key_type_id, file_type='key', kind='new'))
                Certificate.load(self._get_path(cert_id, key_type_id,
                                                file_type='cert', kind='new', cert_type='full_chain'))
                logger.debug("%s / %s loaded successfully, we need another version")
            except (OSError, X509Error):
                if pathlib.Path(self._get_symlink_path(cert_id, 'new')).exists():
                    logger.debug("Skipping version creation for %s / %s", cert_id, key_type_id)
                    return

        cert_version = uuid.uuid4().hex
        logger.info("Creating new certificate version %s for %s", cert_version, cert_id)
        path = os.path.join(self.certs_path, cert_id, cert_version)
        os.makedirs(path, mode=0o750)

        symlink_path = self._get_symlink_path(cert_id, kind=ACMEChief.new_symlink_name)
        try:
            os.unlink(symlink_path)
        except FileNotFoundError:
            # During the initial certificate generation this is expected
            pass
        os.symlink(os.path.basename(path), symlink_path, target_is_directory=True)

    def _get_symlink_path(self, cert_id, kind='live'):
        return os.path.join(self.certs_path, cert_id, kind)

    def _get_ocsp_symlink_path(self, cert_id, key_type_id, kind='live', cert_type='full_chain_key'):
        part_name = CERTIFICATE_TYPES[cert_type]['file_name'].format(key_type_id=key_type_id)
        file_name = f'{part_name}.ocsp'
        return os.path.join(self.certs_path, cert_id, kind, file_name)

    def _get_path(self, cert_id, key_type_id, file_type='cert', kind='live', cert_type='cert_only'):
        if file_type == 'cert':
            file_name = CERTIFICATE_TYPES[cert_type]['file_name'].format(key_type_id=key_type_id)
        elif file_type == 'key':
            file_name = f'{key_type_id}.key'
        elif file_type == 'ocsp':
            file_name = f'{key_type_id}.ocsp'
        else:
            raise ValueError(f'Unknown file_type {file_type}')

        return os.path.join(self.certs_path, cert_id, kind, file_name)

    def _set_cert_status(self):
        """
        Figures out the current status for every configured certificate
        """
        state = collections.defaultdict(dict)

        def _get_certificate_status(cert_id, key_type_id, certificate):  # pylint: disable=too-many-return-statements
            try:
                new_cert_path = self._get_path(cert_id, key_type_id, file_type='cert',
                                               kind='new', cert_type='full_chain')
                new_cert = Certificate.load(new_cert_path)
                if new_cert.certificate.not_valid_before > certificate.certificate.not_valid_before:
                    return CertificateStatus.CERTIFICATE_STAGED
            except OSError:
                pass

            if certificate.self_signed is True:
                return CertificateStatus.SELF_SIGNED

            if datetime.datetime.utcnow() > certificate.certificate.not_valid_after:
                logger.warning("Certificate %s type %s expired on %s", cert_id, key_type_id,
                               certificate.certificate.not_valid_after)
                return CertificateStatus.EXPIRED

            if certificate.needs_renew():
                return CertificateStatus.NEEDS_RENEWAL

            cur_cn = certificate.common_name.lower()
            new_cn = self.config.certificates[cert_id]['CN'].lower()
            if cur_cn != new_cn:
                logger.warning(
                    'Certificate %s type %s has CN %s but is configured for %s, moving back to re-issue',
                    cert_id, key_type_id, cur_cn, new_cn
                )
                return CertificateStatus.SUBJECTS_CHANGED

            cur_sans = {san.lower() for san in certificate.subject_alternative_names}
            new_sans = {san.lower() for san in self.config.certificates[cert_id]['SNI']}
            if cur_sans != new_sans:
                logger.warning(
                    'Certificate %s type %s has SANs %s but is configured for %s, moving back to re-issue',
                    cert_id, key_type_id, cur_sans, new_sans
                )
                return CertificateStatus.SUBJECTS_CHANGED

            return CertificateStatus.VALID

        for cert_id in self.config.certificates:
            for key_type_id in KEY_TYPES:
                try:
                    current_status = self.cert_status[cert_id][key_type_id]
                    if current_status in (CertificateStatus.CSR_PUSHED, CertificateStatus.CHALLENGES_PUSHED,
                                          CertificateStatus.CHALLENGES_REJECTED, CertificateStatus.CERTIFICATE_ISSUED,
                                          CertificateStatus.ACMECHIEF_ERROR, CertificateStatus.ACMEDIR_ERROR):
                        # we don't want to break the current cert. issue process
                        continue
                except KeyError:
                    pass

                try:
                    certificate = Certificate.load(self._get_path(cert_id, key_type_id, file_type='cert', kind='live'))
                    new_status = _get_certificate_status(cert_id, key_type_id, certificate)
                except (OSError, X509Error):
                    new_status = CertificateStatus.INITIAL

                state[cert_id][key_type_id] = CertificateState(new_status)

        return state

    def run(self):
        """
        Starts up the certificate management
        """
        self.certificate_management()

    def sighup_handler(self, *_):
        """
        This is called whenever our process receives SIGHUP signals, it reloads our config and
        authorized hosts data.
        It is also called once at the beginning to perform initial setup.
        """
        logger.info("SIGHUP received")
        self.config = ACMEChiefConfig.load(file_name=self.config_path, confd_path=self.confd_path)
        if self.cert_status:
            previous_status = copy.deepcopy(self.cert_status)
        else:
            previous_status = None
        self.cert_status = self._set_cert_status()
        if previous_status:
            removed_certs = previous_status.keys() - self.cert_status.keys()
            if removed_certs:
                logger.info("Removed certificates: %s", removed_certs)
            new_certs = self.cert_status.keys() - previous_status.keys()
            if new_certs:
                logger.info("New configured certificates: %s", new_certs)
        counters = collections.Counter()
        for cert_id in self.cert_status:
            for key_type_id in KEY_TYPES:
                cert_status = self.cert_status[cert_id][key_type_id].status.name
                counters[cert_status] += 1
        logger.info("Number of certificates per status: %s", counters)
        self.create_initial_certs()

    def create_initial_certs(self):
        """
        Creates initial certificates for everything that doesn't currently exist.
        This is so that web servers which depend on having a certificate to start can start and
        begin serving traffic so they can forward ACME challenges through to us - that will enable
        us to request a real certificate to replace our initial one.
        """
        for cert_id in self.cert_status:
            for key_type_id, key_type_details in KEY_TYPES.items():
                if self.cert_status[cert_id][key_type_id].status != CertificateStatus.INITIAL:
                    continue
                self._create_new_certificate_version(cert_id, key_type_id=key_type_id)

                logger.info("Creating initial self-signed certificate for %s / %s", cert_id, key_type_id)
                key = key_type_details['class']()
                key.generate(**key_type_details['params'])
                key.save(self._get_path(cert_id, key_type_id, file_type='key', kind='new'))

                cert = Certificate(SelfSignedCertificate(
                    private_key=key,
                    common_name="Snakeoil cert",
                    sans=(),
                    from_date=datetime.datetime.utcnow(),
                    until_date=datetime.datetime.utcnow() + datetime.timedelta(days=3),
                ).pem)
                for cert_type, cert_type_details in CERTIFICATE_TYPES.items():
                    if cert_type_details['embedded_key']:
                        embedded_key = key
                    else:
                        embedded_key = None
                    cert.save(self._get_path(cert_id, key_type_id, file_type='cert', kind='new', cert_type=cert_type),
                              mode=cert_type_details['save_mode'], embedded_key=embedded_key,
                              alternative_chain=cert_type_details['alternative_chain'])
                self.cert_status[cert_id][key_type_id].status = CertificateStatus.SELF_SIGNED
                self._push_live_certificate(cert_id)

    def _get_acme_session(self, cert_details):
        acme_account_id = cert_details.get('account', self.config.default_account)
        if acme_account_id not in self.acme_sessions:
            for account in self.config.accounts:  # TODO: avoid O(n) on retrieving account details
                if account['id'] == acme_account_id:
                    directory_url = account['directory']
                    logger.debug("Creating a new ACME Requests session for account %s", acme_account_id)
                    self.acme_sessions[acme_account_id] = ACMERequests(ACMEAccount.load(acme_account_id,
                                                                                        base_path=self.accounts_path,
                                                                                        directory_url=directory_url))
        return self.acme_sessions[acme_account_id]

    def _trigger_dns_zone_update(self, challenges):
        """Triggers a DNS zone update. returns True if everything goes as expected. False otherwise"""
        logger.info("Triggering DNS zone update...")
        cmd = self.config.challenges[ACMEChallengeType.DNS01]['zone_update_cmd']
        remote_servers = self.config.challenges[ACMEChallengeType.DNS01]['sync_dns_servers']
        timeout = self.config.challenges[ACMEChallengeType.DNS01]['zone_update_cmd_timeout']
        params = ['--remote-servers'] + remote_servers + ['--']
        for challenge in challenges:
            params.append(challenge.validation_domain_name)
            params.append(challenge.validation)

        logger.info("Running subprocess %s", [cmd] + params)
        try:
            subprocess.check_call([cmd] + params,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL,
                                  timeout=timeout)
        except subprocess.CalledProcessError as cpe:
            logger.error("Unexpected return code spawning DNS zone updater: %d", cpe.returncode)
            return False
        except subprocess.TimeoutExpired:
            logger.error("Unable to update DNS zone in %d seconds", timeout)
            return False

        return True

    def _prevalidate(self, cert_id, key_type_id):
        logger.info("Prevalidating CN and SNI list for %s / %s", cert_id, key_type_id)
        cert_details = self.config.certificates[cert_id]
        issuing_ca = self.config.challenges[ACMEChallengeType.DNS01]['issuing_ca']
        if cert_details['challenge'] == 'dns-01':
            valid_ns_servers = self.config.challenges[ACMEChallengeType.DNS01]['ns_records']
            pre_validator = DNS01ACMEValidator(issuing_ca=issuing_ca, valid_ns_servers=valid_ns_servers)
        else:
            pre_validator = HTTP01ACMEValidator(issuing_ca=issuing_ca)

        if not pre_validator.validate(cert_details['CN']):
            logger.warning("Aborting new certificate. Prevalidation failed for CN %s for %s / %s",
                           cert_details['CN'], cert_id, key_type_id)
            return False

        skipped_snis = set()
        for sni in set(cert_details['SNI']) - {cert_details['CN']}:
            if not pre_validator.validate(sni):
                logger.warning("Prevalidation failed for SNI %s for %s / %s", sni, cert_id, key_type_id)
                if not cert_details['skip_invalid_snis']:
                    logger.warning("Aborting new certficate due to prevalidation failure for %s / %s",
                                   cert_id, key_type_id)
                    return False
                skipped_snis.add(sni)

        if skipped_snis:
            logger.warning("Skipping the following SNIs: %s for %s / %s", skipped_snis, cert_id, key_type_id)
            cert_details['SNI'] = list(set(cert_details['SNI']) - skipped_snis)

        return True

    def _new_certificate(self, cert_id, key_type_id):
        """Handles new certificate requests. It does the following steps:
            - Generates and persists on disk a private key of key_type_id type
            - Generates and persists a CSR signed by the previously generated key
            - Passes the ball to the next status handler
        """
        logger.info("Handling new certificate event for %s / %s", cert_id, key_type_id)
        cert_details = self.config.certificates[cert_id]

        if cert_details['prevalidate'] and not self._prevalidate(cert_id, key_type_id):
            return CertificateStatus.PREVALIDATION_FAILED

        self._create_new_certificate_version(cert_id, key_type_id=key_type_id)

        key_type_details = KEY_TYPES[key_type_id]
        private_key = key_type_details['class']()
        private_key.generate(**key_type_details['params'])
        private_key.save(self._get_path(cert_id, key_type_id, file_type='key', kind='new'))

        csr_filename = f'{cert_id}.{key_type_id}.csr.pem'
        csr_fullpath = os.path.join(self.csrs_path, csr_filename)
        csr = CertificateSigningRequest(
            private_key=private_key,
            common_name=cert_details['CN'],
            sans=cert_details['SNI'],
        )
        csr.save(csr_fullpath)
        session = self._get_acme_session(cert_details)
        challenges = session.push_csr(csr)
        if not challenges:
            logger.info("Skipping challenge validation for certificate %s / %s", cert_id, key_type_id)
            return CertificateStatus.CHALLENGES_PUSHED

        challenge_type = CHALLENGE_TYPES[cert_details['challenge']]
        if challenge_type not in challenges:
            logger.warning("Unable to get required challenge type %s for certificate %s / %s",
                           challenge_type, cert_id, key_type_id)
            return CertificateStatus.ACMECHIEF_ERROR
        try:
            for challenge in challenges[challenge_type]:
                challenge.save(os.path.join(self.challenges_path[challenge_type],
                                            challenge.file_name))
        except OSError:
            logger.exception("OSError encountered while saving challenge type %s for certificate %s / %s",
                             challenge_type, cert_id, key_type_id)
            return CertificateStatus.ACMECHIEF_ERROR

        if challenge_type == ACMEChallengeType.DNS01:
            if not self._trigger_dns_zone_update(challenges[challenge_type]):
                logger.warning("Failed to perform DNS zone update for certificate %s / %s",
                               cert_id, key_type_id)
                return CertificateStatus.ACMECHIEF_ERROR

        status = CertificateStatus.CSR_PUSHED
        status = self._handle_pushed_csr(cert_id, key_type_id)

        return status

    def _handle_pushed_csr(self, cert_id, key_type_id):
        """Handles PUSHED_CSR status. Performs the following actions:
            - Checks that challenges have been validated
            - Passes the ball to the next status handle
        """
        logger.info("Handling pushed CSR event for %s / %s", cert_id, key_type_id)
        try:
            private_key = PrivateKeyLoader.load(self._get_path(cert_id, key_type_id, file_type='key', kind='new'))
        except (OSError, X509Error):
            logger.exception("Failed to load new private key for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.ACMECHIEF_ERROR

        cert_details = self.config.certificates[cert_id]

        csr_id = CertificateSigningRequest.generate_csr_id(
            public_key_pem=private_key.public_pem,
            common_name=cert_details['CN'],
            sans=cert_details['SNI'],
        )

        challenge_type = CHALLENGE_TYPES[cert_details['challenge']]

        session = self._get_acme_session(cert_details)

        try:
            challenges = session.challenges[csr_id][challenge_type]
        except KeyError:
            logger.exception("Could not find challenge for challenge type %s, certificate %s / %s",
                             challenge_type, cert_id, key_type_id)
            return CertificateStatus.ACMECHIEF_ERROR

        for challenge in challenges:
            if challenge.challenge_type is ACMEChallengeType.DNS01:
                validation_params = {'dns_servers':
                                     self.config.challenges[ACMEChallengeType.DNS01]['validation_dns_servers'],
                                     'dns_port':
                                     self.config.challenges[ACMEChallengeType.DNS01]['resolver_port']}
            else:
                validation_params = {}

            if challenge.validate(**validation_params) is not ACMEChallengeValidation.VALID:
                # keep the issuance process in this step till all the challenges have been validated
                logger.warning("Unable to validate challenge %s", challenge)
                return CertificateStatus.CSR_PUSHED

        status = CertificateStatus.CHALLENGES_VALIDATED
        status = self._handle_validated_challenges(cert_id, key_type_id)

        return status

    def _handle_validated_challenges(self, cert_id, key_type_id):
        """Handles CHALLENGES_VALIDATED status. Performs the following actions:
            - pushes solved challenges to the ACME directory
            - Passes the ball to the next status handler
        """
        logger.info("Handling validated challenges event for %s / %s", cert_id, key_type_id)
        try:
            private_key = PrivateKeyLoader.load(self._get_path(cert_id, key_type_id, file_type='key', kind='new'))
        except (OSError, X509Error):
            logger.exception("Failed to load new private key for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.ACMECHIEF_ERROR

        cert_details = self.config.certificates[cert_id]

        csr_id = CertificateSigningRequest.generate_csr_id(
            public_key_pem=private_key.public_pem,
            common_name=cert_details['CN'],
            sans=cert_details['SNI'],
        )
        session = self._get_acme_session(cert_details)
        challenge_type = CHALLENGE_TYPES[cert_details['challenge']]
        try:
            session.push_solved_challenges(csr_id, challenge_type=challenge_type)
        except ACMEOrderNotFound:
            # unable to find CSR in current ACME session, go back to the initial step
            logger.exception("Could not find ACME order when pushing solved challenges for challenge type %s, "
                             "certificate %s / %s",
                             challenge_type, cert_id, key_type_id)
            return CertificateStatus.ACMECHIEF_ERROR

        try:
            return self._handle_pushed_challenges(cert_id, key_type_id)
        except ACMEOrderNotFound:
            logger.exception("Could not find ACME order when handling pushed challenges for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.ACMECHIEF_ERROR
        except ACMEError:
            logger.exception("ACMEError when handling pushed challenges for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.CHALLENGES_PUSHED

    def _handle_pushed_challenges(self, cert_id, key_type_id):  # pylint: disable=too-many-return-statements
        """Handles CHALLENGES_PUSHED status. Performs the following actions:
            - Attempts to finalize the ACME order.
            - Passes the ball to the next status handler.
        """
        logger.info("Handling pushed challenges event for %s / %s", cert_id, key_type_id)
        try:
            private_key = PrivateKeyLoader.load(self._get_path(cert_id, key_type_id, file_type='key', kind='new'))
        except (OSError, X509Error):
            logger.exception("Failed to load new private key for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.ACMECHIEF_ERROR

        cert_details = self.config.certificates[cert_id]

        csr_id = CertificateSigningRequest.generate_csr_id(
            public_key_pem=private_key.public_pem,
            common_name=cert_details['CN'],
            sans=cert_details['SNI'],
        )

        session = self._get_acme_session(cert_details)
        try:
            session.finalize_order(csr_id)
        except ACMEChallengeNotValidatedError:
            logger.warning("ACME Directory hasn't validated the challenge(s) yet for certificate %s / %s",
                           cert_id, key_type_id)
            return CertificateStatus.CHALLENGES_PUSHED
        except ACMEInvalidChallengeError:
            logger.warning("ACME Directory has rejected the challenge(s) for certificate %s / %s",
                           cert_id, key_type_id)
            return CertificateStatus.CHALLENGES_REJECTED
        except ACMEOrderNotFound:
            logger.exception("Could not find ACME order when attempting to get the certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.ACMECHIEF_ERROR
        except ACMEError:
            logger.exception("Problem getting certificate for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.ACMEDIR_ERROR

        status = CertificateStatus.ORDER_FINALIZED
        status = self._handle_order_finalized(cert_id, key_type_id)

        return status

    def _handle_order_finalized(self, cert_id, key_type_id):
        """Handles ORDER_FINALIZED status. Performs the following actions:
            - Attempts to fetch the signed certificate from the ACME directory
            - Persists the certificate on disk
        """
        logger.info("Handling order finalized event for %s / %s", cert_id, key_type_id)
        try:
            private_key = PrivateKeyLoader.load(self._get_path(cert_id, key_type_id, file_type='key', kind='new'))
        except (OSError, X509Error):
            logger.exception("Failed to load new private key for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.ACMECHIEF_ERROR

        cert_details = self.config.certificates[cert_id]

        csr_id = CertificateSigningRequest.generate_csr_id(
            public_key_pem=private_key.public_pem,
            common_name=cert_details['CN'],
            sans=cert_details['SNI'],
        )

        session = self._get_acme_session(cert_details)

        try:
            certificate = session.get_certificate(csr_id)
        except ACMETimeoutFetchingCertificateError:
            logger.exception("Unable to fetch certificate for an already finalized order for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.ORDER_FINALIZED
        except ACMEIssuedCertificateError:
            logger.warning("Unable to handle certificate issued by the ACME directory for certificate %s / %s",
                           cert_id, key_type_id)
            return CertificateStatus.CERTIFICATE_ISSUED
        except ACMEError:
            logger.exception("Problem getting certificate for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.ACMEDIR_ERROR

        try:
            for cert_type, cert_type_details in CERTIFICATE_TYPES.items():
                if cert_type_details['embedded_key']:
                    embedded_key = private_key
                else:
                    embedded_key = None
                certificate.save(self._get_path(cert_id, key_type_id, file_type='cert',
                                                kind='new', cert_type=cert_type),
                                 mode=cert_type_details['save_mode'], embedded_key=embedded_key,
                                 alternative_chain=cert_type_details['alternative_chain'])
        except OSError:
            logger.exception("Problem persisting certificate %s / %s on disk", cert_id, key_type_id)
            return CertificateStatus.CERTIFICATE_ISSUED

        return self._handle_ready_to_be_pushed(cert_id, key_type_id)

    def _handle_ready_to_be_pushed(self, cert_id, key_type_id):
        """Handles READY_TO_BE_PUSHED status. Performs the following actions:
            - Validates the staging time
            - Attempts to push the certificate if the staging time has been honored or is a new certificate
              being issued for the first time.
        """
        bypass_staging_time_checks = False
        try:
            live_cert = Certificate.load(self._get_path(cert_id, key_type_id, file_type='cert', kind='live'))
            if live_cert.self_signed:
                bypass_staging_time_checks = True
        except (OSError, X509Error):
            bypass_staging_time_checks = True

        if bypass_staging_time_checks:
            logger.info("Bypassing staging_time for %s / %s", cert_id, key_type_id)
            return self._push_live_certificate(cert_id)

        logger.info("Enforcing staging_time for %s / %s", cert_id, key_type_id)

        try:
            cert = Certificate.load(self._get_path(cert_id, key_type_id,
                                                   file_type='cert', kind='new', cert_type='full_chain'))
            staging_timedelta = self.config.certificates[cert_id]['staging_time']
            if cert.certificate.not_valid_before >= (datetime.datetime.utcnow() - staging_timedelta):
                logger.info("Staging_time will be enforced for %s / %s till %s",
                            cert_id, key_type_id, cert.certificate.not_valid_before + staging_timedelta)
                return CertificateStatus.CERTIFICATE_STAGED
        except (OSError, X509Error):
            logger.exception("Problem verifying not valid before date on certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.CERTIFICATE_ISSUED

        return self._push_live_certificate(cert_id)

    def _push_live_certificate(self, cert_id):
        """Updates the live symlink after checking that every key_type_id is ready and every certificate type
            has been generated."""
        new_symlink = pathlib.Path(self._get_symlink_path(cert_id, ACMEChief.new_symlink_name))
        live_symlink = pathlib.Path(self._get_symlink_path(cert_id, ACMEChief.live_symlink_name))
        if new_symlink.exists() and live_symlink.exists() and new_symlink.resolve() == live_symlink.resolve():
            return CertificateStatus.VALID

        logger.info("Pushing the new certificate for %s", cert_id)
        for key_type_id in KEY_TYPES:
            try:
                _ = PrivateKeyLoader.load(self._get_path(cert_id, key_type_id, file_type='key', kind='new'))
                _ = Certificate.load(self._get_path(cert_id, key_type_id,
                                                    file_type='cert', kind='new', cert_type='full_chain'))
            except FileNotFoundError:
                logger.info("Waiting till %s / %s is generated to be able to push the new certificate",
                            cert_id, key_type_id)
                return CertificateStatus.READY_TO_BE_PUSHED
            except (OSError, X509Error):
                logger.exception("Problem pushing live certificate %s / %s",
                                 cert_id, key_type_id)
                return CertificateStatus.CERTIFICATE_ISSUED

        try:
            os.unlink(live_symlink)
        except FileNotFoundError:
            pass
        except OSError:
            logger.exception("Problem pushing live certificate %s", cert_id)
            return CertificateStatus.CERTIFICATE_ISSUED

        try:
            symlink_source = new_symlink.resolve()
            os.symlink(os.path.basename(symlink_source), live_symlink, target_is_directory=True)
        except OSError:
            logger.exception("Problem pushing live certificate %s", cert_id)
            return CertificateStatus.CERTIFICATE_ISSUED

        return CertificateStatus.VALID

    def _fetch_ocsp_response(self, cert_id, key_type_id):
        """Fetches OCSP responses for certificates in VALID or CERTIFICATE_STAGED states"""
        for kind in ('live', 'new'):
            cert = Certificate.load(self._get_path(cert_id, key_type_id,
                                                   file_type='cert', kind=kind, cert_type='full_chain'))
            if cert.ocsp_uri is None:
                continue

            ocsp_response_path = self._get_path(cert_id, key_type_id, file_type='ocsp', kind=kind)
            cert_details = self.config.certificates[cert_id]
            refresh = False
            try:
                ocsp_response = OCSPResponse.load(ocsp_response_path)
                if ocsp_response.next_update - datetime.datetime.utcnow() < cert_details['ocsp_update_threshold']:
                    refresh = True
            except FileNotFoundError:
                refresh = True
            except (OSError, OCSPResponseError):
                logger.exception('Unexpected error opening %s OCSP response for %s / %s', kind, cert_id, key_type_id)
                refresh = True

            if not refresh:
                continue

            logger.info("Refreshing %s OCSP response for certificate %s / %s", kind, cert_id, key_type_id)

            ocsp_request = OCSPRequest(cert, cert.chain[1])
            try:
                ocsp_response = ocsp_request.fetch_response()
                ocsp_response.save(ocsp_response_path)
                logger.info("%s OCSP response refreshed successfully for %s / %s", kind, cert_id, key_type_id)
                # Provide a symlink to the OCSP response for
                # cert_type=[full_chain_key|full_alt_chain_key] with ".ocsp" suffix
                for ocsp_symlink_cert_type in ('full_chain_key', 'full_alt_chain_key'):
                    ocsp_response_symlink_path = self._get_ocsp_symlink_path(cert_id, key_type_id,
                                                                             kind=kind,
                                                                             cert_type=ocsp_symlink_cert_type)
                    ocsp_symlink = pathlib.Path(ocsp_response_symlink_path)
                    if not ocsp_symlink.exists():
                        symlink_source = os.path.basename(ocsp_response_path)
                        os.symlink(symlink_source, ocsp_symlink, target_is_directory=False)
            except (OCSPRequestError, OCSPResponseError):
                logger.exception("Unable to fetch %s OCSP response for %s / %s", kind, cert_id, key_type_id)
            except OSError:
                logger.exception("Unable to persist %s OCSP response for %s / %s on disk", kind, cert_id, key_type_id)

    def certificate_management(self):
        """
        This functions is started in a thread to perform regular tasks.
        It will begin attempting to request real certificates from the certificate authority.
        In future it will attempt to renew existing certificates.
        """
        logger.info("Starting main loop...")
        while True:
            for cert_id in self.cert_status:
                for key_type_id in KEY_TYPES:
                    cert_state = self.cert_status[cert_id][key_type_id]
                    if not cert_state.retry:
                        logger.debug("Skipping certificate %s till at least %s", cert_id, cert_state.next_retry)
                        continue
                    if cert_state.status is CertificateStatus.VALID:
                        self._fetch_ocsp_response(cert_id, key_type_id)
                        continue
                    if cert_state.status in (CertificateStatus.SELF_SIGNED,
                                             CertificateStatus.NEEDS_RENEWAL,
                                             CertificateStatus.EXPIRED,
                                             CertificateStatus.SUBJECTS_CHANGED,
                                             CertificateStatus.CHALLENGES_REJECTED,
                                             CertificateStatus.CERTIFICATE_ISSUED,
                                             CertificateStatus.ACMECHIEF_ERROR,
                                             CertificateStatus.ACMEDIR_ERROR):
                        new_status = self._new_certificate(cert_id, key_type_id)
                    elif cert_state.status is CertificateStatus.CSR_PUSHED:
                        new_status = self._handle_pushed_csr(cert_id, key_type_id)
                    elif cert_state.status is CertificateStatus.CHALLENGES_PUSHED:
                        new_status = self._handle_pushed_challenges(cert_id, key_type_id)
                    elif cert_state.status is CertificateStatus.ORDER_FINALIZED:
                        new_status = self._handle_order_finalized(cert_id, key_type_id)
                    elif cert_state.status is CertificateStatus.CERTIFICATE_STAGED:
                        new_status = self._handle_ready_to_be_pushed(cert_id, key_type_id)
                        self._fetch_ocsp_response(cert_id, key_type_id)
                    elif cert_state.status is CertificateStatus.READY_TO_BE_PUSHED:
                        new_status = self._push_live_certificate(cert_id)
                        self._fetch_ocsp_response(cert_id, key_type_id)
                    else:
                        logger.error("Unexpected state: %s", cert_state.status)
                        continue

                    self.cert_status[cert_id][key_type_id].status = new_status
            sleep(5)


def main():
    """
    Main backend entry point.
    """
    parser = argparse.ArgumentParser(description="""Runs the ACMEChief backend. This is
    responsible for maintaining your configured certificates - creating dummy self-signed
    ones to start with, then having them replaced with ones from your ACME server. This does
    not provide the ACMEChief API.""")
    parser.add_argument('--version', action='version', version='0.31')
    parser.parse_args()
    ACMEChief().run()


if __name__ == '__main__':
    main()
