import os
import tempfile
import unittest

from certcentral import CertCentral, CertCentralConfig

VALID_CONFIG_EXAMPLE = '''
accounts:
  - id: ee566f9e436e120082f0770c0d58dd6d
    directory: https://acme-staging-v02.api.letsencrypt.org/directory
    default: true
  - id: 621b49f9c6ccbbfbff9acb6e18f71205
    directory: https://127.0.0.1:14000/dir
certificates:
  default_account_certificate:
    CN: certcentraltest.beta.wmflabs.org
    SNI:
        - certcentraltest.beta.wmflabs.org
  non_default_account_certificate:
    account: 621b49f9c6ccbbfbff9acb6e18f71205
    CN: 'test.wmflabs.org'
    SNI:
        - '*.test.wmflabs.org'
'''

VALID_CONFIG_EXAMPLE_WITHOUT_DEFAULT_ACCOUNT = '''
accounts:
  - id: 621b49f9c6ccbbfbff9acb6e18f71205
    directory: https://127.0.0.1:14000/dir
  - id: ee566f9e436e120082f0770c0d58dd6d
    directory: https://acme-staging-v02.api.letsencrypt.org/directory
certificates:
  default_account_certificate:
    CN: certcentraltest.beta.wmflabs.org
    SNI:
        - certcentraltest.beta.wmflabs.org
  non_default_account_certificate:
    account: 621b49f9c6ccbbfbff9acb6e18f71205
    CN: 'test.wmflabs.org'
    SNI:
        - '*.test.wmflabs.org'
'''

CONFD_VALID_FILE_EXAMPLE = '''
certname: default_account_certificate
hostname: deployment-certcentral-testclient02.deployment-prep.eqiad.wmflabs
'''


class CertCentralConfigTest(unittest.TestCase):
    def setUp(self):
        self.base_path = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.base_path.name, CertCentral.config_path)
        self.confd_path = os.path.join(self.base_path.name, CertCentral.confd_path)
        os.mkdir(self.confd_path)

        with open(os.path.join(self.confd_path, 'confd_file_example.yaml'), 'w') as confd_file:
            confd_file.write(CONFD_VALID_FILE_EXAMPLE)

    def tearDown(self):
        self.base_path.cleanup()

    def test_config_parsing(self):
        with open(self.config_path, 'w') as config_file:
            config_file.write(VALID_CONFIG_EXAMPLE)

        config = CertCentralConfig.load(self.config_path, confd_path=self.confd_path)
        self.assertEqual(len(config.accounts), 2)
        self.assertEqual(len(config.certificates), 2)
        self.assertEqual(config.default_account, 'ee566f9e436e120082f0770c0d58dd6d')
        self.assertIn('default_account_certificate', config.authorized_hosts)

    def test_config_without_explicit_default(self):
        with open(self.config_path, 'w') as config_file:
            config_file.write(VALID_CONFIG_EXAMPLE_WITHOUT_DEFAULT_ACCOUNT)

        config = CertCentralConfig.load(self.config_path, confd_path=self.confd_path)
        self.assertEqual(config.default_account, '621b49f9c6ccbbfbff9acb6e18f71205')
