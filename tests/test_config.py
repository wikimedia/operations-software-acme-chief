import os
import tempfile
import unittest
from datetime import timedelta
from unittest import mock

from acme_chief.acme_chief import ACMEChief
from acme_chief.acme_requests import ACMEChallengeType
from acme_chief.config import ACMEChiefConfig

VALID_CONFIG_EXAMPLE = '''
accounts:
  - id: ee566f9e436e120082f0770c0d58dd6d
    directory: https://acme-staging-v02.api.letsencrypt.org/directory
    default: true
  - id: 621b49f9c6ccbbfbff9acb6e18f71205
    directory: https://127.0.0.1:14000/dir
certificates:
  default_account_certificate:
    CN: acmechieftest.beta.wmflabs.org
    SNI:
        - acmechieftest.beta.wmflabs.org
    challenge: http-01
    authorized_hosts:
        - deployment-acmechief-testclient03.deployment-prep.eqiad.wmflabs
  non_default_account_certificate:
    account: 621b49f9c6ccbbfbff9acb6e18f71205
    CN: 'test.wmflabs.org'
    SNI:
        - '*.test.wmflabs.org'
    challenge: dns-01
    staging_time: 7200
    prevalidate: true
    skip_invalid_snis: true
  certificate_auth_by_regex:
    CN: regex.test.wmflabs.org
    SNI:
        - regex.test.wmflabs.org
    challenge: http-01
    authorized_regexes:
        - '^deployment-acmechief-testclient0[1-3]\.deployment-prep\.eqiad\.wmflabs$'
    staging_time: 3600
challenges:
    dns-01:
        validation_dns_servers:
            - 127.0.0.1
        sync_dns_servers:
            - 127.0.0.1
        zone_update_cmd: /usr/bin/dns-update-zone
        zone_update_cmd_timeout: 30.5
        issuing_ca: 'letsencrypt.org'
        ns_records:
        - ns0.wikimedia.org.
        - ns1.wikimedia.org.
        - ns2.wikimedia.org.
api:
    clients_root_directory: /etc/custom-root-directory
'''

VALID_CONFIG_EXAMPLE_WITHOUT_DEFAULT_ACCOUNT = '''
accounts:
  - id: 621b49f9c6ccbbfbff9acb6e18f71205
    directory: https://127.0.0.1:14000/dir
  - id: ee566f9e436e120082f0770c0d58dd6d
    directory: https://acme-staging-v02.api.letsencrypt.org/directory
certificates:
  default_account_certificate:
    CN: acmechieftest.beta.wmflabs.org
    SNI:
        - acmechieftest.beta.wmflabs.org
    challenge: http-01
    staging_time: 3600
  non_default_account_certificate:
    account: 621b49f9c6ccbbfbff9acb6e18f71205
    CN: 'test.wmflabs.org'
    SNI:
        - '*.test.wmflabs.org'
    challenge: dns-01
    staging_time: 3600
challenges:
    dns-01:
        validation_dns_servers:
            - 127.0.0.1
        sync_dns_servers:
            - 127.0.0.1
'''

CONFD_VALID_FILE_EXAMPLE = '''
certname: default_account_certificate
hostname: deployment-acmechief-testclient02.deployment-prep.eqiad.wmflabs
'''

class ACMEChiefConfigTest(unittest.TestCase):
    def setUp(self):
        self.base_path = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.base_path.name, ACMEChief.config_path)
        self.confd_path = os.path.join(self.base_path.name, ACMEChief.confd_path)
        os.mkdir(self.confd_path)

        with open(os.path.join(self.confd_path, 'confd_file_example.yaml'), 'w') as confd_file:
            confd_file.write(CONFD_VALID_FILE_EXAMPLE)

    def tearDown(self):
        self.base_path.cleanup()

    @mock.patch('os.access', return_value=True)
    def test_config_parsing(self, access_mock):
        with open(self.config_path, 'w') as config_file:
            config_file.write(VALID_CONFIG_EXAMPLE)

        config = ACMEChiefConfig.load(self.config_path, confd_path=self.confd_path)
        self.assertEqual(len(config.accounts), 2)
        self.assertEqual(len(config.certificates), 3)
        self.assertEqual(config.default_account, 'ee566f9e436e120082f0770c0d58dd6d')
        self.assertIn('default_account_certificate', config.authorized_hosts)
        self.assertIn('deployment-acmechief-testclient02.deployment-prep.eqiad.wmflabs',
                      config.authorized_hosts['default_account_certificate'])
        self.assertIn('deployment-acmechief-testclient03.deployment-prep.eqiad.wmflabs',
                      config.authorized_hosts['default_account_certificate'])
        self.assertIn(ACMEChallengeType.DNS01, config.challenges)
        self.assertEqual(config.certificates['default_account_certificate']['staging_time'],
                         timedelta(seconds=3600))
        self.assertEqual(config.certificates['non_default_account_certificate']['staging_time'],
                         timedelta(seconds=7200))
        self.assertFalse(config.certificates['default_account_certificate']['prevalidate'])
        self.assertTrue(config.certificates['non_default_account_certificate']['prevalidate'])
        self.assertFalse(config.certificates['default_account_certificate']['skip_invalid_snis'])
        self.assertTrue(config.certificates['non_default_account_certificate']['skip_invalid_snis'])
        self.assertIn(config.certificates['non_default_account_certificate']['CN'],
                      config.certificates['non_default_account_certificate']['SNI'])
        self.assertEqual(config.challenges[ACMEChallengeType.DNS01]['zone_update_cmd'], '/usr/bin/dns-update-zone')
        self.assertEqual(config.challenges[ACMEChallengeType.DNS01]['zone_update_cmd_timeout'], 30.5)
        access_mock.assert_called_once_with('/usr/bin/dns-update-zone', os.X_OK)
        self.assertEqual(config.challenges[ACMEChallengeType.DNS01]['issuing_ca'], 'letsencrypt.org')
        self.assertEqual(config.challenges[ACMEChallengeType.DNS01]['ns_records'], ['ns0.wikimedia.org.',
                                                                                    'ns1.wikimedia.org.',
                                                                                    'ns2.wikimedia.org.'])
        self.assertEqual(config.challenges[ACMEChallengeType.DNS01]['resolver_port'], 53)
        self.assertEqual(config.api['clients_root_directory'], '/etc/custom-root-directory')

    def test_config_without_explicit_default(self):
        with open(self.config_path, 'w') as config_file:
            config_file.write(VALID_CONFIG_EXAMPLE_WITHOUT_DEFAULT_ACCOUNT)

        config = ACMEChiefConfig.load(self.config_path, confd_path=self.confd_path)
        self.assertEqual(config.default_account, '621b49f9c6ccbbfbff9acb6e18f71205')

    def test_access_check(self):
        with open(self.config_path, 'w') as config_file:
            config_file.write(VALID_CONFIG_EXAMPLE)

        config = ACMEChiefConfig.load(self.config_path, confd_path=self.confd_path)
        self.assertTrue(config.check_access('deployment-acmechief-testclient03.deployment-prep.eqiad.wmflabs',
                                            'default_account_certificate'))
        self.assertTrue(config.check_access('deployment-acmechief-testclient02.deployment-prep.eqiad.wmflabs',
                                            'default_account_certificate'))
        self.assertFalse(config.check_access('deployment-acmechief-testclient04.deployment-prep.eqiad.wmflabs',
                                             'default_account_certificate'))

        self.assertTrue(config.check_access('deployment-acmechief-testclient03.deployment-prep.eqiad.wmflabs',
                                            'certificate_auth_by_regex'))
        self.assertTrue(config.check_access('deployment-acmechief-testclient02.deployment-prep.eqiad.wmflabs',
                                            'certificate_auth_by_regex'))
        self.assertFalse(config.check_access('deployment-acmechief-testclient04.deployment-prep.eqiad.wmflabs',
                                             'certificate_auth_by_regex'))

    @mock.patch.dict('os.environ', {}, clear=True)
    def test_watchdog_usec_not_present(self):
        self.assertNotIn('WATCHDOG_USEC', os.environ) # sanity check

        with open(self.config_path, 'w') as config_file:
            config_file.write(VALID_CONFIG_EXAMPLE)

        config = ACMEChiefConfig.load(self.config_path, confd_path=self.confd_path)
        self.assertFalse(config.watchdog['systemd'])

    @mock.patch.dict('os.environ', {'WATCHDOG_USEC': '0'}, clear=True)
    def test_watchdog_usec_is_zero(self):
        with open(self.config_path, 'w') as config_file:
            config_file.write(VALID_CONFIG_EXAMPLE)

        config = ACMEChiefConfig.load(self.config_path, confd_path=self.confd_path)
        self.assertFalse(config.watchdog['systemd'])

    @mock.patch.dict('os.environ', {'WATCHDOG_USEC': '1000'}, clear=True)
    def test_watchdog_usec_enabled(self):
        with open(self.config_path, 'w') as config_file:
            config_file.write(VALID_CONFIG_EXAMPLE)

        config = ACMEChiefConfig.load(self.config_path, confd_path=self.confd_path)
        self.assertTrue(config.watchdog['systemd'])
