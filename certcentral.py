# Central certificates service
# Alex Monk <krenair@gmail.com>, May/June 2018

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
import collections
import datetime
import os
import signal
import time
from enum import Enum

import yaml
from cryptography.hazmat.primitives.asymmetric import ec

from acme_requests import (ACMEAccount, ACMEChallengeType, ACMEError,
                           ACMEOrderNotFound, ACMERequests)
from x509 import (Certificate, CertificateSigningRequest, ECPrivateKey,
                  PrivateKeyLoader, RSAPrivateKey, SelfSignedCertificate,
                  X509Error)

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


class CertificateStatus(Enum):
    """Certificate status definition"""
    INITIAL = 1
    SELF_SIGNED = 2         # initial self-signed certificate issued to let services start
    CSR_PUSHED = 3          # CSR pushed to the ACME directory and challenges saved on disk
    CHALLENGES_PUSHED = 4   # Challenges pushed to the ACME directory
    VALID = 5               # Valid certificate
    NEEDS_RENEWAL = 6       # Valid certificate that needs to be renew soon!
    EXPIRED = 7             # Expired certificate


class CertCentralConfig:
    """Class representing CertCentral configuration"""
    def __init__(self, *, accounts, certificates, default_account, authorized_hosts):
        self.accounts = accounts
        self.certificates = certificates
        self.default_account = default_account
        self.authorized_hosts = authorized_hosts

    @staticmethod
    def load(file_name, confd_path=None):
        """Load a config from the specified file_name and an optional conf.d path"""
        if confd_path is None:
            confd_path = os.path.dirname(file_name)

        with open(file_name) as config_file:
            config = yaml.safe_load(config_file)

        default_account = CertCentralConfig._get_default_account(config['accounts'])

        authorized_hosts = collections.defaultdict(list)
        for fname in os.listdir(confd_path):
            with open(os.path.join(confd_path, fname)) as conf_f:
                conf_data = yaml.safe_load(conf_f)
                if conf_data['certname'] not in config['certificates']:
                    # TODO: log a warning
                    continue
                authorized_hosts[conf_data['certname']].append(conf_data['hostname'])

        return CertCentralConfig(accounts=config['accounts'],
                                 certificates=config['certificates'],
                                 default_account=default_account,
                                 authorized_hosts=authorized_hosts)

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
    account_key_path = 'acct.key'
    csrs_path = 'csrs'
    config_path = 'config.yaml'
    confd_path = 'conf.d'
    http_challenges_path = 'http_challenges'

    def __init__(self, base_path=BASEPATH):
        self.live_certs_path = os.path.join(base_path, CertCentral.live_certs_path)
        self.account_key_path = os.path.join(base_path, CertCentral.account_key_path)
        self.csrs_path = os.path.join(base_path, CertCentral.csrs_path)
        self.config_path = os.path.join(base_path, CertCentral.config_path)
        self.confd_path = os.path.join(base_path, CertCentral.confd_path)
        self.http_challenges_path = os.path.join(base_path, CertCentral.http_challenges_path)
        self.config = None
        self.acme_sessions = dict()
        self.cert_status = collections.defaultdict(dict)
        signal.signal(signal.SIGHUP, self.sighup_handler)
        self.sighup_handler()

    def _get_live_path(self, cert_id, key_type_id, public=True):
        if public:
            part = 'public'
        else:
            part = 'private'

        file_name = '{}.{}.{}.pem'.format(cert_id, key_type_id, part)
        return os.path.join(self.live_certs_path, file_name)

    def _set_cert_status(self):
        """
        Figures out the current status for every configured certificate
        """
        status = collections.defaultdict(dict)

        def _get_certificate_status(certificate):
            if certificate.self_signed is True:
                return CertificateStatus.SELF_SIGNED

            if datetime.datetime.utcnow() > certificate.certificate.not_valid_after:
                # TODO: log a warning
                return CertificateStatus.EXPIRED

            if certificate.needs_renew():
                return CertificateStatus.NEEDS_RENEWAL

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
                    certificate = Certificate.load(self._get_live_path(cert_id, key_type_id, public=True))
                    status[cert_id][key_type_id] = _get_certificate_status(certificate)
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

                key = key_type_details['class']()
                key.generate(**key_type_details['params'])
                key.save(self._get_live_path(cert_id, key_type_id, public=False))

                cert = SelfSignedCertificate(
                    private_key=key,
                    common_name="Snakeoil cert",
                    sans=(),
                    from_date=datetime.datetime.utcnow(),
                    until_date=datetime.datetime.utcnow() + datetime.timedelta(days=3),
                )
                cert.save(self._get_live_path(cert_id, key_type_id, public=True))
                self.cert_status[cert_id][key_type_id] = CertificateStatus.SELF_SIGNED

    def _get_acme_session(self, cert_details):
        acme_account_id = cert_details.get('account', self.config.default_account)
        if acme_account_id not in self.acme_sessions:
            for account in self.config.accounts:  # TODO: avoid O(n) on retrieving account details
                if account['id'] == acme_account_id:
                    directory_url = account['directory']
                    self.acme_sessions[acme_account_id] = ACMERequests(ACMEAccount.load(acme_account_id,
                                                                                        directory_url=directory_url))
        return self.acme_sessions[acme_account_id]

    def _new_certificate(self, cert_id, key_type_id):
        """Handles new certificate requests. It does the following steps:
            - Generates and persists on disk a private key of key_type_id type
            - Generates and persists a CSR signed by the previously generated key
            - Passes the ball to the next status handler
        """
        cert_details = self.config.certificates[cert_id]
        key_type_details = KEY_TYPES[key_type_id]
        private_key = key_type_details['class']()
        private_key.generate(**key_type_details['params'])
        private_key.save(self._get_live_path(cert_id, key_type_id, public=False))

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
        try:
            for challenge in challenges[ACMEChallengeType.HTTP01]:
                challenge.save(os.path.join(self.http_challenges_path,
                                            challenge.file_name))
        except OSError:
            return CertificateStatus.SELF_SIGNED

        status = CertificateStatus.CSR_PUSHED
        status = self._handle_pushed_csr(cert_id, key_type_id)
        if status is CertificateStatus.CHALLENGES_PUSHED:
            status = self._handle_pushed_challenges(cert_id, key_type_id)

        return status

    def _handle_pushed_csr(self, cert_id, key_type_id):
        """Handles PUSHED_CSR status. Performs the following actions:
            - pushes solved challenges to the ACME directory
            - Passes the ball to the next status handler
        """
        try:
            private_key = PrivateKeyLoader.load(self._get_live_path(cert_id, key_type_id, public=False))
        except (OSError, X509Error):
            return CertificateStatus.SELF_SIGNED

        cert_details = self.config.certificates[cert_id]

        csr_id = CertificateSigningRequest.generate_csr_id(
            public_key_pem=private_key.public_pem,
            common_name=cert_details['CN'],
            sans=cert_details['SNI'],
        )
        session = self._get_acme_session(cert_details)
        try:
            session.push_solved_challenges(csr_id, challenge_type=ACMEChallengeType.HTTP01)
        except ACMEOrderNotFound:
            # unable to find CSR in current ACME session, go back to the initial step
            return CertificateStatus.SELF_SIGNED

        try:
            return self._handle_pushed_challenges(cert_id, key_type_id)
        except ACMEOrderNotFound:
            return CertificateStatus.SELF_SIGNED
        except ACMEError:
            return CertificateStatus.CHALLENGES_PUSHED

    def _handle_pushed_challenges(self, cert_id, key_type_id):
        """Handles CHALLENGES_PUSHED status. Performs the following actions:
            - Attempts to fetch the signed certificate from the ACME directory
            - Persists the certificate on disk
        """
        try:
            private_key = PrivateKeyLoader.load(self._get_live_path(cert_id, key_type_id, public=False))
        except (OSError, X509Error):
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
        except ACMEOrderNotFound:
            return CertificateStatus.SELF_SIGNED

        if certificate is None:
            return CertificateStatus.CHALLENGES_PUSHED

        certificate.save(self._get_live_path(cert_id, key_type_id, public=True))
        return CertificateStatus.VALID

    def certificate_management(self):
        """
        This functions is started in a thread to perform regular tasks.
        It will begin attempting to request real certificates from the certificate authority.
        In future it will attempt to renew existing certificates.
        """
        while True:
            for cert_id in self.cert_status:
                for key_type_id in KEY_TYPES:
                    cert_status = self.cert_status[cert_id][key_type_id]
                    if cert_status is CertificateStatus.VALID:
                        continue
                    elif cert_status in [CertificateStatus.SELF_SIGNED,
                                         CertificateStatus.NEEDS_RENEWAL,
                                         CertificateStatus.EXPIRED]:
                        new_status = self._new_certificate(cert_id, key_type_id)
                    elif cert_status is CertificateStatus.CSR_PUSHED:
                        new_status = self._handle_pushed_csr(cert_id, key_type_id)
                    elif cert_status is CertificateStatus.CHALLENGES_PUSHED:
                        new_status = self._handle_pushed_challenges(cert_id, key_type_id)
                    else:
                        print("Unexpected state: {}".format(cert_status))
                        continue

                    self.cert_status[cert_id][key_type_id] = new_status
            time.sleep(5)


if __name__ == '__main__':
    CertCentral().run()
