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
import datetime
import logging
import logging.config
import os
import signal
import subprocess
from enum import Enum
from time import sleep

import yaml
from cryptography.hazmat.primitives.asymmetric import ec

from certcentral.acme_requests import (ACMEAccount, ACMEChallengeType,
                                       ACMEChallengeValidation, ACMEError,
                                       ACMEInvalidChallengeError,
                                       ACMEOrderNotFound, ACMERequests)
from certcentral.x509 import (Certificate, CertificateSaveMode,
                              CertificateSigningRequest, ECPrivateKey,
                              PrivateKeyLoader, RSAPrivateKey,
                              SelfSignedCertificate, X509Error)

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

BASEPATH = '/etc/certcentral'
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
        'certcentral': {
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
        'file_name': '{cert_id}.{key_type_id}.crt',
    },
    'chain_only': {
        'save_mode': CertificateSaveMode.CHAIN_ONLY,
        'file_name': '{cert_id}.{key_type_id}.chain.crt',
    },
    'full_chain': {
        'save_mode': CertificateSaveMode.FULL_CHAIN,
        'file_name': '{cert_id}.{key_type_id}.chained.crt',
    }
}

CHALLENGE_TYPES = {
    'dns-01': ACMEChallengeType.DNS01,
    'http-01': ACMEChallengeType.HTTP01,
}

DEFAULT_DNS_ZONE_UPDATE_CMD = '/bin/echo'
DEFAULT_DNS_ZONE_UPDATE_CMD_TIMEOUT = 60.0


class CertificateStatus(Enum):
    """Certificate status definition"""
    INITIAL = 1
    SELF_SIGNED = 2           # initial self-signed certificate issued to let services start
    CSR_PUSHED = 3            # CSR pushed to the ACME directory and challenges saved on disk
    CHALLENGES_VALIDATED = 4  # Challenges have been successfully validated
    CHALLENGES_PUSHED = 5     # Challenges pushed to the ACME directory
    VALID = 6                 # Valid certificate
    NEEDS_RENEWAL = 7         # Valid certificate that needs to be renew soon!
    EXPIRED = 8               # Expired certificate
    SUBJECTS_CHANGED = 9      # Configuration of cert (CN/SANs) has changed, need to re-issue


class CertCentralConfig:
    """Class representing CertCentral configuration"""
    def __init__(self, *, accounts, certificates, default_account, authorized_hosts, challenges):
        self.accounts = accounts
        self.certificates = certificates
        self.default_account = default_account
        self.authorized_hosts = authorized_hosts
        self.challenges = {}
        for challenge_type, challenge_config in challenges.items():
            if challenge_type == 'dns-01':
                if not ('zone_update_cmd' in challenge_config and os.access(challenge_config['zone_update_cmd'],
                                                                            os.X_OK)):
                    logger.warning("Missing/invalid DNS zone updater CMD, using the default one: %s",
                                   DEFAULT_DNS_ZONE_UPDATE_CMD)
                    challenge_config['zone_update_cmd'] = DEFAULT_DNS_ZONE_UPDATE_CMD

                try:
                    challenge_config['zone_update_cmd_timeout'] = float(challenge_config['zone_update_cmd_timeout'])
                except (KeyError, ValueError):
                    logger.warning("Missing/invalid DNS zone updater CMD timeout, using the default one: %.2f",
                                   DEFAULT_DNS_ZONE_UPDATE_CMD_TIMEOUT)
                    challenge_config['zone_update_cmd_timeout'] = DEFAULT_DNS_ZONE_UPDATE_CMD_TIMEOUT

                self.challenges[ACMEChallengeType.DNS01] = challenge_config
            elif challenge_type == 'http-01':
                self.challenges[ACMEChallengeType.HTTP01] = challenge_config
            else:
                logger.warning("Unexpected challenge type found in configuration: %s", challenge_type)

        if ACMEChallengeType.DNS01 not in self.challenges:
            logger.warning('Missing dns-01 challenge configuration')

    @staticmethod
    def load(file_name, confd_path=None):
        """Load a config from the specified file_name and an optional conf.d path"""
        logger.debug("Loading config file: %s", file_name)
        if confd_path is None:
            confd_path = os.path.dirname(file_name)

        with open(file_name) as config_file:
            config = yaml.safe_load(config_file)

        default_account = CertCentralConfig._get_default_account(config['accounts'])

        authorized_hosts = collections.defaultdict(list)
        for fname in os.listdir(confd_path):
            file_path = os.path.join(confd_path, fname)
            logger.debug("Loading config file: %s", file_path)
            with open(file_path) as conf_f:
                conf_data = yaml.safe_load(conf_f)
                if conf_data['certname'] not in config['certificates']:
                    logger.warning("Certificate %s referenced on %s not found in general config",
                                   conf_data['certname'], file_path)
                    continue
                authorized_hosts[conf_data['certname']].append(conf_data['hostname'])

        return CertCentralConfig(accounts=config['accounts'],
                                 certificates=config['certificates'],
                                 default_account=default_account,
                                 authorized_hosts=authorized_hosts,
                                 challenges=config['challenges'])

    @staticmethod
    def _get_default_account(accounts):
        for account in accounts:
            if 'default' in account and account['default'] is True:
                return account['id']

        return accounts[0]['id']


class CertCentral():
    """
    This class just acts as a container for all the methods and state - config and authorized hosts
    data.
    """
    live_certs_path = 'live_certs'
    new_certs_path = 'new_certs'
    accounts_path = 'accounts'
    csrs_path = 'csrs'
    config_path = 'config.yaml'
    confd_path = 'conf.d'
    http_challenges_path = 'http_challenges'
    dns_challenges_path = 'dns_challenges'

    def __init__(self, base_path=BASEPATH):
        self._configure_logging()
        self.live_certs_path = os.path.join(base_path, CertCentral.live_certs_path)
        self.new_certs_path = os.path.join(base_path, CertCentral.new_certs_path)
        self.accounts_path = os.path.join(base_path, CertCentral.accounts_path)
        self.csrs_path = os.path.join(base_path, CertCentral.csrs_path)
        self.config_path = os.path.join(base_path, CertCentral.config_path)
        self.confd_path = os.path.join(base_path, CertCentral.confd_path)
        self.challenges_path = {
            ACMEChallengeType.DNS01: os.path.join(base_path, CertCentral.dns_challenges_path),
            ACMEChallengeType.HTTP01: os.path.join(base_path, CertCentral.http_challenges_path),
        }
        self.config = None
        self.acme_sessions = dict()
        self.cert_status = collections.defaultdict(dict)
        signal.signal(signal.SIGHUP, self.sighup_handler)
        self.sighup_handler()

    @staticmethod
    def _configure_logging():
        """Configure logging"""
        logging.config.dictConfig(LOGGING_CONFIG)

    def _get_path(self, cert_id, key_type_id, public=True, kind='live', cert_type='cert_only'):
        if public:
            file_name = CERTIFICATE_TYPES[cert_type]['file_name'].format(cert_id=cert_id, key_type_id=key_type_id)
        else:
            file_name = '{}.{}.key'.format(cert_id, key_type_id)

        if kind == 'live':
            base = self.live_certs_path
        else:
            base = self.new_certs_path

        return os.path.join(base, file_name)

    def _set_cert_status(self):
        """
        Figures out the current status for every configured certificate
        """
        status = collections.defaultdict(dict)

        def _get_certificate_status(cert_id, key_type_id, certificate):
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
                    if current_status in [CertificateStatus.CSR_PUSHED, CertificateStatus.CHALLENGES_PUSHED]:
                        # we don't want to break the current cert. issue process
                        continue
                except KeyError:
                    pass

                try:
                    certificate = Certificate.load(self._get_path(cert_id, key_type_id, public=True, kind='live'))
                    status[cert_id][key_type_id] = _get_certificate_status(cert_id, key_type_id, certificate)
                except (OSError, X509Error):
                    status[cert_id][key_type_id] = CertificateStatus.INITIAL

        return status

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
        self.config = CertCentralConfig.load(file_name=self.config_path, confd_path=self.confd_path)
        self.cert_status = self._set_cert_status()
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
                if self.cert_status[cert_id][key_type_id] != CertificateStatus.INITIAL:
                    continue

                logger.info("Creating initial self-signed certificate for %s / %s", cert_id, key_type_id)
                key = key_type_details['class']()
                key.generate(**key_type_details['params'])
                key.save(self._get_path(cert_id, key_type_id, public=False, kind='live'))

                cert = Certificate(SelfSignedCertificate(
                    private_key=key,
                    common_name="Snakeoil cert",
                    sans=(),
                    from_date=datetime.datetime.utcnow(),
                    until_date=datetime.datetime.utcnow() + datetime.timedelta(days=3),
                ).pem)
                for cert_type, cert_type_details in CERTIFICATE_TYPES.items():
                    path = self._get_path(cert_id, key_type_id, public=True, kind='live', cert_type=cert_type)
                    cert.save(path, mode=cert_type_details['save_mode'])
                self.cert_status[cert_id][key_type_id] = CertificateStatus.SELF_SIGNED

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

    def _new_certificate(self, cert_id, key_type_id):
        """Handles new certificate requests. It does the following steps:
            - Generates and persists on disk a private key of key_type_id type
            - Generates and persists a CSR signed by the previously generated key
            - Passes the ball to the next status handler
        """
        logger.info("Handling new certificate event for %s / %s", cert_id, key_type_id)
        cert_details = self.config.certificates[cert_id]
        key_type_details = KEY_TYPES[key_type_id]
        private_key = key_type_details['class']()
        private_key.generate(**key_type_details['params'])
        private_key.save(self._get_path(cert_id, key_type_id, public=False, kind='new'))

        csr_filename = '{}.{}.csr.pem'.format(cert_id, key_type_id)
        csr_fullpath = os.path.join(self.csrs_path, csr_filename)
        csr = CertificateSigningRequest(
            private_key=private_key,
            common_name=cert_details['CN'],
            sans=cert_details['SNI'],
        )
        csr.save(csr_fullpath)
        session = self._get_acme_session(cert_details)
        challenges = session.push_csr(csr)
        challenge_type = CHALLENGE_TYPES[cert_details['challenge']]
        if challenge_type not in challenges:
            logger.warning("Unable to get required challenge type %s for certificate %s / %s",
                           challenge_type, cert_id, key_type_id)
            return CertificateStatus.SELF_SIGNED
        try:
            for challenge in challenges[challenge_type]:
                challenge.save(os.path.join(self.challenges_path[challenge_type],
                                            challenge.file_name))
        except OSError:
            logger.exception("OSError encountered while saving challenge type %s for certificate %s / %s",
                             challenge_type, cert_id, key_type_id)
            return CertificateStatus.SELF_SIGNED

        if challenge_type == ACMEChallengeType.DNS01:
            if not self._trigger_dns_zone_update(challenges[challenge_type]):
                logger.warning("Failed to perform DNS zone update for certificate %s / %s",
                               cert_id, key_type_id)
                return CertificateStatus.SELF_SIGNED

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
            private_key = PrivateKeyLoader.load(self._get_path(cert_id, key_type_id, public=False, kind='new'))
        except (OSError, X509Error):
            logger.exception("Failed to load new private key for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.SELF_SIGNED

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
            return CertificateStatus.SELF_SIGNED

        for challenge in challenges:
            if challenge.challenge_type is ACMEChallengeType.DNS01:
                validation_params = {'dns_servers':
                                     self.config.challenges[ACMEChallengeType.DNS01]['validation_dns_servers']}
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
            private_key = PrivateKeyLoader.load(self._get_path(cert_id, key_type_id, public=False, kind='new'))
        except (OSError, X509Error):
            logger.exception("Failed to load new private key for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.SELF_SIGNED

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
            return CertificateStatus.SELF_SIGNED

        try:
            return self._handle_pushed_challenges(cert_id, key_type_id)
        except ACMEOrderNotFound:
            logger.exception("Could not find ACME order when handling pushed challenges for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.SELF_SIGNED
        except ACMEError:
            logger.exception("ACMEError when handling pushed challenges for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.CHALLENGES_PUSHED

    def _handle_pushed_challenges(self, cert_id, key_type_id):
        """Handles CHALLENGES_PUSHED status. Performs the following actions:
            - Attempts to fetch the signed certificate from the ACME directory
            - Persists the certificate on disk
        """
        logger.info("Handling pushed challenges event for %s / %s", cert_id, key_type_id)
        try:
            private_key = PrivateKeyLoader.load(self._get_path(cert_id, key_type_id, public=False, kind='new'))
        except (OSError, X509Error):
            logger.exception("Failed to load new private key for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.SELF_SIGNED

        cert_details = self.config.certificates[cert_id]

        csr_id = CertificateSigningRequest.generate_csr_id(
            public_key_pem=private_key.public_pem,
            common_name=cert_details['CN'],
            sans=cert_details['SNI'],
        )

        session = self._get_acme_session(cert_details)
        try:
            certificate = session.get_certificate(csr_id)
        except (ACMEOrderNotFound, ACMEInvalidChallengeError):
            logger.exception("Problem getting certificate for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.SELF_SIGNED
        except ACMEError:
            logger.exception("Problem getting certificate for certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.CHALLENGES_PUSHED

        if certificate is None:
            logger.warning("Returned certificate is None for certificate %s / %s",
                           cert_id, key_type_id)
            return CertificateStatus.CHALLENGES_PUSHED

        certificate.save(self._get_path(cert_id, key_type_id, public=True, kind='new', cert_type='full_chain'),
                         mode=CertificateSaveMode.FULL_CHAIN)
        return self._push_live_certificate(cert_id, key_type_id)

    def _push_live_certificate(self, cert_id, key_type_id):
        """Moves a new certificate to the live path after checking that everything looks sane"""
        logger.info("Pushing the new certificate for %s / %s", cert_id, key_type_id)
        try:
            private_key = PrivateKeyLoader.load(self._get_path(cert_id, key_type_id, public=False, kind='new'))
            cert = Certificate.load(self._get_path(cert_id, key_type_id,
                                                   public=True, kind='new', cert_type='full_chain'))
            private_key.save(self._get_path(cert_id, key_type_id, public=False, kind='live'))
            for cert_type, cert_type_details in CERTIFICATE_TYPES.items():
                cert.save(self._get_path(cert_id, key_type_id, public=True, kind='live', cert_type=cert_type),
                          mode=cert_type_details['save_mode'])
        except (OSError, X509Error):
            logger.exception("Problem pushing live certificate %s / %s",
                             cert_id, key_type_id)
            return CertificateStatus.SELF_SIGNED

        return CertificateStatus.VALID

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
                    cert_status = self.cert_status[cert_id][key_type_id]
                    if cert_status is CertificateStatus.VALID:
                        continue
                    elif cert_status in (CertificateStatus.SELF_SIGNED,
                                         CertificateStatus.NEEDS_RENEWAL,
                                         CertificateStatus.EXPIRED,
                                         CertificateStatus.SUBJECTS_CHANGED):
                        new_status = self._new_certificate(cert_id, key_type_id)
                    elif cert_status is CertificateStatus.CSR_PUSHED:
                        new_status = self._handle_pushed_csr(cert_id, key_type_id)
                    elif cert_status is CertificateStatus.CHALLENGES_PUSHED:
                        new_status = self._handle_pushed_challenges(cert_id, key_type_id)
                    else:
                        logger.error("Unexpected state: %s", cert_status)
                        continue

                    self.cert_status[cert_id][key_type_id] = new_status
            sleep(5)


def main():
    """
    Main backend entry point.
    """
    parser = argparse.ArgumentParser(description="""Runs the CertCentral backend. This is
    responsible for maintaining your configured certificates - creating dummy self-signed
    ones to start with, then having them replaced with ones from your ACME server. This does
    not provide the CertCentral API.""")
    parser.add_argument('--version', action='version', version='0.1')
    parser.parse_args()
    CertCentral().run()


if __name__ == '__main__':
    main()
