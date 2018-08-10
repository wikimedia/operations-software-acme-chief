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
import tempfile
import time
import traceback

import yaml
from cryptography.hazmat.primitives.asymmetric import ec

from acme_requests import ACMEAccount, ACMEChallengeType, ACMERequests
from x509 import (CertificateSigningRequest, ECPrivateKey, RSAPrivateKey,
                  SelfSignedCertificate)

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
        signal.signal(signal.SIGHUP, self.sighup_handler)
        self.sighup_handler()

    def run(self):
        """
        Starts up the certificate management
        """
        self.create_initial_certs()
        self.certificate_management()

    def sighup_handler(self, *_):
        """
        This is called whenever our process receives SIGHUP signals, it reloads our config and
        authorized hosts data.
        It is also called once at the beginning to perform initial setup.
        """
        self.config = CertCentralConfig.load(file_name=self.config_path, confd_path=self.confd_path)

    def create_initial_certs(self):
        """
        Creates initial certificates for everything that doesn't currently exist.
        This is so that web servers which depend on having a certificate to start can start and
        begin serving traffic so they can forward ACME challenges through to us - that will enable
        us to request a real certificate to replace our initial one.
        """
        for cert_id in self.config.certificates:
            for key_type_id, key_type_details in KEY_TYPES.items():
                public_key_filename = '{}.{}.public.pem'.format(cert_id, key_type_id)
                public_key_file = os.path.join(self.live_certs_path, public_key_filename)
                private_key_filename = '{}.{}.private.pem'.format(cert_id, key_type_id)
                private_key_file = os.path.join(self.live_certs_path, private_key_filename)
                if not os.path.exists(public_key_file) or not os.path.exists(private_key_file):
                    key = key_type_details['class']()
                    key.generate(**key_type_details['params'])
                    key.save(private_key_filename)

                    cert = SelfSignedCertificate(
                        private_key=key,
                        common_name="Snakeoil cert",
                        sans=(),
                        from_date=datetime.datetime.utcnow(),
                        until_date=datetime.datetime.utcnow() + datetime.timedelta(days=3),
                    )
                    cert.save(public_key_file)

    def certificate_management(self):  # pylint: disable=too-many-locals
        """
        This functions is started in a thread to perform regular tasks.
        It will begin attempting to request real certificates from the certificate authority.
        In future it will attempt to renew existing certificates.
        """
        # TODO: make this go through certs and renew where necessary
        have_certs = set()
        while True:
            for cert_id, cert_details in self.config.certificates.items():
                for key_type_id, key_type_details in KEY_TYPES.items():
                    if (cert_id, key_type_id) in have_certs:
                        continue
                    # some of this is borrowed from acme-setup too
                    temp_private_key = tempfile.NamedTemporaryFile()
                    private_key = key_type_details['class']()
                    private_key.generate(**key_type_details['params'])
                    private_key.save(temp_private_key.name)

                    csr_filename = '{}.{}.csr.pem'.format(cert_id, key_type_id)
                    csr_fullpath = os.path.join(self.csrs_path, csr_filename)
                    csr = CertificateSigningRequest(
                        private_key=private_key,
                        common_name=cert_details['CN'],
                        sans=cert_details['SNI'],
                    )
                    csr.save(csr_fullpath)
                    # TODO: do ACME v2 DNS wildcard requests and write challenges to
                    # dns_challenges/{domain}
                    try:
                        # TODO: make this check for /.well-known/acme-challenge file on % of
                        # authorized hosts
                        acme_account_id = cert_details.get('account', self.config.default_account)
                        account = ACMEAccount.load(acme_account_id)
                        session = ACMERequests(account)
                        challenges = session.push_csr(csr)
                        for challenge in challenges[ACMEChallengeType.HTTP01]:
                            challenge.save(os.path.join(self.http_challenges_path, challenge.file_name))

                        session.push_solved_challenges(csr.csr_id, challenge_type=ACMEChallengeType.HTTP01)
                        signed_cert = session.get_certificate(csr.csr_id)
                        if signed_cert is None:     # we were too fast and the ACME directory wasn't able to validate
                                                    # the challenges yet
                            continue

                        public_cert_path = os.path.join(
                            self.live_certs_path,
                            '{}.{}.public.pem'.format(cert_id, key_type_id)
                        )
                        signed_cert.save(public_cert_path)

                        private_key_path = os.path.join(
                            self.live_certs_path,
                            '{}.{}.private.pem'.format(cert_id, key_type_id)
                        )
                        private_key.save(private_key_path)

                        have_certs.update([(cert_id, key_type_id)])
                    except Exception:  # pylint: disable=broad-except
                        traceback.print_exc()
                    temp_private_key.close()
                time.sleep(5)


if __name__ == '__main__':
    CertCentral().run()
