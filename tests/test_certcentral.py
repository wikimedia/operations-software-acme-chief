import os
import shutil
import subprocess
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta

import mock
from cryptography.hazmat.primitives.asymmetric import ec

from certcentral.acme_requests import (ACMEAccount, ACMEChallengeType,
                                       ACMEChallengeValidation, ACMEError,
                                       DNS01ACMEChallenge)
from certcentral.certcentral import (DEFAULT_DNS_ZONE_UPDATE_CMD,
                                     DEFAULT_DNS_ZONE_UPDATE_CMD_TIMEOUT,
                                     KEY_TYPES, CERTIFICATE_TYPES, CertCentral,
                                     CertCentralConfig, CertificateStatus)
from certcentral.x509 import (Certificate, CertificateSaveMode, ECPrivateKey,
                              PrivateKeyLoader, X509Error)
from tests.test_pebble import (BaseDNSRequestHandler,
                               BasePebbleIntegrationTest,
                               HTTP01ChallengeHandler)

DIRECTORY_URL = 'https://127.0.0.1:14000/dir'

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
    challenge: http-01
  non_default_account_certificate:
    account: 621b49f9c6ccbbfbff9acb6e18f71205
    CN: 'test.wmflabs.org'
    SNI:
        - '*.test.wmflabs.org'
    challenge: dns-01
challenges:
    dns-01:
        validation_dns_servers:
            - 127.0.0.1
        sync_dns_servers:
            - 127.0.0.1
        zone_update_cmd: /usr/bin/dns-update-zone
        zone_update_cmd_timeout: 30.5
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
    challenge: http-01
  non_default_account_certificate:
    account: 621b49f9c6ccbbfbff9acb6e18f71205
    CN: 'test.wmflabs.org'
    SNI:
        - '*.test.wmflabs.org'
    challenge: dns-01
challenges:
    dns-01:
        validation_dns_servers:
            - 127.0.0.1
        sync_dns_servers:
            - 127.0.0.1
'''

CONFD_VALID_FILE_EXAMPLE = '''
certname: default_account_certificate
hostname: deployment-certcentral-testclient02.deployment-prep.eqiad.wmflabs
'''

class InfiniteLoopBreaker(Exception):
    """Exception to be raised when time.sleep() is mocked"""


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

    @mock.patch('os.access', return_value=True)
    def test_config_parsing(self, access_mock):
        with open(self.config_path, 'w') as config_file:
            config_file.write(VALID_CONFIG_EXAMPLE)

        config = CertCentralConfig.load(self.config_path, confd_path=self.confd_path)
        self.assertEqual(len(config.accounts), 2)
        self.assertEqual(len(config.certificates), 2)
        self.assertEqual(config.default_account, 'ee566f9e436e120082f0770c0d58dd6d')
        self.assertIn('default_account_certificate', config.authorized_hosts)
        self.assertIn(ACMEChallengeType.DNS01, config.challenges)
        self.assertEqual(config.challenges[ACMEChallengeType.DNS01]['zone_update_cmd'], '/usr/bin/dns-update-zone')
        self.assertEqual(config.challenges[ACMEChallengeType.DNS01]['zone_update_cmd_timeout'], 30.5)
        access_mock.assert_called_once_with('/usr/bin/dns-update-zone', os.X_OK)

    def test_config_without_explicit_default(self):
        with open(self.config_path, 'w') as config_file:
            config_file.write(VALID_CONFIG_EXAMPLE_WITHOUT_DEFAULT_ACCOUNT)

        config = CertCentralConfig.load(self.config_path, confd_path=self.confd_path)
        self.assertEqual(config.default_account, '621b49f9c6ccbbfbff9acb6e18f71205')


class CertCentralTest(unittest.TestCase):
    @mock.patch('signal.signal')
    @mock.patch.object(CertCentral, 'sighup_handler')
    def setUp(self, sighup_handler_mock, signal_mock):
        self.instance = CertCentral()
        self.instance.config = CertCentralConfig(
            accounts=[{'id': '1945e767ad72a532ebca519242a801bf', 'directory': 'https://127.0.0.1:14000/dir'}],
            certificates={
                'test_certificate':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                    'challenge': 'http-01',
                },
            },
            default_account='1945e767ad72a532ebca519242a801bf',
            authorized_hosts={
                'test_certificate': ['localhost']
            },
            challenges={
                'dns-01': {
                    'validation_dns_servers': ['127.0.0.1'],
                    'sync_dns_servers': ['127.0.0.1'],
                }
            }
        )

        signal_mock.assert_called_once()
        sighup_handler_mock.assert_called_once()

    def test_run(self):
        with mock.patch.object(self.instance, 'certificate_management') as certificate_management_mock:
            self.instance.run()

        certificate_management_mock.assert_called_once()

    @mock.patch.object(CertCentralConfig, 'load')
    @mock.patch.object(CertCentral, '_set_cert_status')
    @mock.patch.object(CertCentral, 'create_initial_certs')
    def test_sighup_handler(self, create_initial_certs_mock, set_cert_status_mock, load_mock) :
        self.instance.sighup_handler()

        load_mock_calls = [mock.call(confd_path=self.instance.confd_path, file_name=self.instance.config_path)]
        load_mock.assert_has_calls(load_mock_calls)
        load_mock.assert_called_once()
        set_cert_status_mock.assert_called_once()
        create_initial_certs_mock.assert_called_once()

    @mock.patch('certcentral.certcentral.SelfSignedCertificate')
    @mock.patch('certcentral.certcentral.Certificate')
    def test_create_initial_tests(self, cert_mock, self_signed_cert_mock):
        self.instance.cert_status = {'test_certificate': {
            'ec-prime256v1': CertificateStatus.VALID,
            'rsa-2048': CertificateStatus.INITIAL,
        }}

        ec_key_mock = mock.MagicMock()
        rsa_key_mock = mock.MagicMock()
        ec_key = deepcopy(KEY_TYPES['ec-prime256v1'])
        ec_key['class'] = ec_key_mock
        rsa_key = deepcopy(KEY_TYPES['rsa-2048'])
        rsa_key['class'] = rsa_key_mock

        self_signed_cert_pem = b'-----BEGIN CERTIFICATE-----\nMIIBLjCB1qADAgECAhRxJCFPZ3GhYbLItsUmpIoJSJYR5zAKBggqhkjOPQQDAjAY\nMRYwFAYDVQQDDA1TbmFrZW9pbCBjZXJ0MB4XDTE4MDkwODAwNTQwMVoXDTE4MDkx\nMTAwNTQwMVowGDEWMBQGA1UEAwwNU25ha2VvaWwgY2VydDBZMBMGByqGSM49AgEG\nCCqGSM49AwEHA0IABDqt32diDH9nQxqFRq6v6KKiHqYMHtV17NaRx5MZaYa+W1kV\nfHYsaDgturMPH0mHgwyOIxeDsunNxQ9l9Ky/wPUwCgYIKoZIzj0EAwIDRwAwRAIg\nDKvGUasaWse5Lmv4vK+LuSxOt6bS/R2yqOML+9p1xk8CIHApbLL1bb2M2olXzPOE\ntgBTOv5Voi32fqjBMgXMh/Yd\n-----END CERTIFICATE-----\n'
        type(self_signed_cert_mock.return_value).pem = mock.PropertyMock(return_value=self_signed_cert_pem)
        with mock.patch.dict('certcentral.certcentral.KEY_TYPES', {'ec-prime256v1': ec_key, 'rsa-2048': rsa_key}):
            self.instance.create_initial_certs()

        rsa_key_mock.assert_called_once()
        expected_key_calls = [mock.call(),
                              mock.call().generate(**KEY_TYPES['rsa-2048']['params']),
                              mock.call().save(self.instance._get_path('test_certificate',
                                                                        'rsa-2048',
                                                                        public=False,
                                                                        kind='live'))]
        rsa_key_mock.assert_has_calls(expected_key_calls)
        ec_key_mock.assert_not_called()
        self_signed_cert_mock.assert_called_once()
        name, args, kwargs = self_signed_cert_mock.mock_calls[0]
        self.assertFalse(name)
        self.assertFalse(args)
        self.assertEqual(kwargs['common_name'], 'Snakeoil cert')
        self.assertFalse(kwargs['sans'])
        self.assertEqual(kwargs['private_key'], rsa_key_mock.return_value)
        self.assertLess(kwargs['until_date'] - kwargs['from_date'], timedelta(days=7))
        cert_mock.assert_has_calls([mock.call(self_signed_cert_pem)] + [
            mock.call().save(
                self.instance._get_path('test_certificate',
                                        'rsa-2048',
                                        public=True,
                                        kind='live',
                                        cert_type=cert_type
                ),
                mode=cert_type_details['save_mode']
            )
            for cert_type, cert_type_details in CERTIFICATE_TYPES.items()
        ])

    @mock.patch.object(ACMEAccount, 'load')
    @mock.patch('certcentral.certcentral.ACMERequests')
    def test_get_acme_session(self, requests_mock, account_load_mock):
        session = self.instance._get_acme_session({
            'CN': 'certcentraltest.beta.wmflabs.org',
            'SNI': ['certcentraltest.beta.wmflabs.org'],
        })

        account_load_mock.assert_called_once_with('1945e767ad72a532ebca519242a801bf',
                                                  base_path=self.instance.accounts_path,
                                                  directory_url='https://127.0.0.1:14000/dir')
        requests_mock.assert_called_once_with(account_load_mock.return_value)
        self.assertEqual(session, requests_mock.return_value)

    @mock.patch.object(PrivateKeyLoader, 'load')
    @mock.patch.object(Certificate, 'load')
    @mock.patch.object(CertCentral, '_get_path')
    def test_push_live_certificate(self, get_path_mock, certificate_load_mock, pkey_load_mock):
        self.instance._push_live_certificate('test_certificate', 'rsa-2048')

        get_path_new_calls = [mock.call('test_certificate', 'rsa-2048', kind='new', public=False),
                              mock.call('test_certificate', 'rsa-2048',
                                        cert_type='full_chain', kind='new', public=True)]
        get_path_mock.assert_has_calls(get_path_new_calls, any_order=True)
        get_path_live_calls = [mock.call('test_certificate', 'rsa-2048', kind='live', public=False),
                               mock.call('test_certificate', 'rsa-2048',
                                         cert_type='cert_only', kind='live', public=True),
                               mock.call('test_certificate', 'rsa-2048',
                                         cert_type='chain_only', kind='live', public=True),
                               mock.call('test_certificate', 'rsa-2048',
                                         cert_type='full_chain', kind='live', public=True)]
        get_path_mock.assert_has_calls(get_path_live_calls, any_order=True)
        certificate_load_mock_calls = [mock.call(get_path_mock.return_value),
                                       mock.call().save(get_path_mock.return_value,
                                                        mode=CertificateSaveMode.CERT_ONLY),
                                       mock.call().save(get_path_mock.return_value,
                                                        mode=CertificateSaveMode.CHAIN_ONLY),
                                       mock.call().save(get_path_mock.return_value,
                                                        mode=CertificateSaveMode.FULL_CHAIN)]
        certificate_load_mock.assert_has_calls(certificate_load_mock_calls, any_order=True)
        pkey_load_calls = [mock.call(get_path_mock.return_value), mock.call().save(get_path_mock.return_value)]
        pkey_load_mock.assert_has_calls(pkey_load_calls)

    @mock.patch('subprocess.check_call')
    def test_update_dns_zone(self, check_call_mock):
        challenges = [DNS01ACMEChallenge('_acme-challenge.wmflabs.test', 'fake-challenge1'),
                      DNS01ACMEChallenge('_acme-challenge.wmflabs.test', 'fake-challenge2')]
        ret_value = self.instance._trigger_dns_zone_update(challenges)
        self.assertTrue(ret_value)
        params = ['--remote-servers']
        params += self.instance.config.challenges[ACMEChallengeType.DNS01]['sync_dns_servers']
        params += ['--']

        for challenge in challenges:
            params.append(challenge.validation_domain_name)
            params.append(challenge.validation)

        cmd = self.instance.config.challenges[ACMEChallengeType.DNS01]['zone_update_cmd']
        timeout = self.instance.config.challenges[ACMEChallengeType.DNS01]['zone_update_cmd_timeout']
        check_call_mock.assert_called_once_with([cmd] + params,
                                                stderr=subprocess.DEVNULL,
                                                stdout=subprocess.DEVNULL,
                                                timeout=timeout)

    @mock.patch('subprocess.check_call')
    def test_update_dns_zone_hyphens(self, check_call_mock):
        """
        This ensures that if challenges begin with hyphen they do not appear in the DNS zone
        update command before the double hyphen, to prevent them being misinterpreted.
        """
        challenges = [DNS01ACMEChallenge('_acme-challenge.wmflabs.test', '-fake-challenge1'),
                      DNS01ACMEChallenge('_acme-challenge.wmflabs.test', '-fake-challenge2')]
        self.instance._trigger_dns_zone_update(challenges)
        args, _ = check_call_mock.call_args
        self.assertEqual(len(args), 1)
        params, = args

        self.assertIn('--', params)
        for check_param in params[:params.index('--')]:
            self.assertNotIn(check_param, ['-fake-challenge1', '-fake-challenge2'])

    @mock.patch('subprocess.check_call')
    def test_update_dns_zone_timeout(self, check_call_mock):
        cmd = self.instance.config.challenges[ACMEChallengeType.DNS01]['zone_update_cmd']
        timeout = self.instance.config.challenges[ACMEChallengeType.DNS01]['zone_update_cmd_timeout']
        check_call_mock.side_effect = subprocess.TimeoutExpired([cmd], timeout)
        ret_value = self.instance._trigger_dns_zone_update([])
        self.assertFalse(ret_value)

    @mock.patch('subprocess.check_call')
    def test_update_dns_zone_error(self, check_call_mock):
        cmd = self.instance.config.challenges[ACMEChallengeType.DNS01]['zone_update_cmd']
        check_call_mock.side_effect = subprocess.CalledProcessError(1, [cmd])
        ret_value = self.instance._trigger_dns_zone_update([])
        self.assertFalse(ret_value)

    def test_certificate_management(self):
        for status in [CertificateStatus.SELF_SIGNED,
                       CertificateStatus.NEEDS_RENEWAL,
                       CertificateStatus.EXPIRED]:
            self.instance.cert_status = {'test_certificate': {
                'ec-prime256v1': status,
                'rsa-2048': status,
            }}
            with mock.patch('certcentral.certcentral.sleep', side_effect=InfiniteLoopBreaker) as sleep_mock:
                with mock.patch.object(self.instance, '_new_certificate') as new_certificate_mock:
                    new_certificate_mock.return_value = CertificateStatus.VALID
                    with self.assertRaises(InfiniteLoopBreaker):
                        self.instance.certificate_management()

            sleep_mock.assert_called_once()

            for key_type_id, cert_status in self.instance.cert_status['test_certificate'].items():
                new_certificate_mock.assert_any_call('test_certificate', key_type_id)
                self.assertEqual(cert_status, new_certificate_mock.return_value)

            self.instance.cert_status = {'test_certificate': {
                'ec-prime256v1': CertificateStatus.CSR_PUSHED,
                'rsa-2048': CertificateStatus.CSR_PUSHED,
            }}

            with mock.patch('certcentral.certcentral.sleep', side_effect=InfiniteLoopBreaker) as sleep_mock:
                with mock.patch.object(self.instance, '_handle_pushed_csr') as handle_pushed_csr_mock:
                    handle_pushed_csr_mock.return_value = CertificateStatus.CHALLENGES_PUSHED
                    with self.assertRaises(InfiniteLoopBreaker):
                        self.instance.certificate_management()

            sleep_mock.assert_called_once()

            for key_type_id, cert_status in self.instance.cert_status['test_certificate'].items():
                handle_pushed_csr_mock.assert_any_call('test_certificate', key_type_id)
                self.assertEqual(cert_status, handle_pushed_csr_mock.return_value)

            self.instance.cert_status = {'test_certificate': {
                'ec-prime256v1': CertificateStatus.CHALLENGES_PUSHED,
                'rsa-2048': CertificateStatus.CHALLENGES_PUSHED,
            }}

            with mock.patch('certcentral.certcentral.sleep', side_effect=InfiniteLoopBreaker) as sleep_mock:
                with mock.patch.object(self.instance, '_handle_pushed_challenges') as handle_pushed_challenges_mock:
                    handle_pushed_challenges_mock.return_value = CertificateStatus.VALID
                    with self.assertRaises(InfiniteLoopBreaker):
                        self.instance.certificate_management()

            sleep_mock.assert_called_once()

            for key_type_id, cert_status in self.instance.cert_status['test_certificate'].items():
                handle_pushed_challenges_mock.assert_any_call('test_certificate', key_type_id)
                self.assertEqual(cert_status, handle_pushed_challenges_mock.return_value)


class CertCentralStatusTransitionTests(unittest.TestCase):
    @mock.patch('signal.signal')
    @mock.patch.object(CertCentral, 'sighup_handler')
    @mock.patch('os.access', return_value=True)
    def setUp(self, signal_mock, sighup_handler_mock, access_mock):
        self.instance = CertCentral()

        self.instance.config = CertCentralConfig(
            accounts=[{'id': '1945e767ad72a532ebca519242a801bf', 'directory': 'https://127.0.0.1:14000/dir'}],
            certificates={
                'test_certificate':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                    'challenge': 'http-01',
                },
                'test_certificate_dns01':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                    'challenge': 'dns-01',
                },
            },
            default_account='1945e767ad72a532ebca519242a801bf',
            authorized_hosts={
                'test_certificate': ['localhost']
            },
            challenges={
                'dns-01': {
                    'validation_dns_servers': ['127.0.0.1'],
                    'sync_dns_servers': ['127.0.0.1'],
                    'zone_update_cmd': '/usr/bin/update-zone-dns',
                }
            }
        )

        self.patchers = []

        self.ec_key_mock = mock.MagicMock()
        self.rsa_key_mock = mock.MagicMock()
        ec_key = deepcopy(KEY_TYPES['ec-prime256v1'])
        ec_key['class'] = self.ec_key_mock
        rsa_key = deepcopy(KEY_TYPES['rsa-2048'])
        rsa_key['class'] = self.rsa_key_mock

        self.patchers.append(mock.patch.dict('certcentral.certcentral.KEY_TYPES',
                                             {'ec-prime256v1': ec_key, 'rsa-2048': rsa_key}))
        self.patchers[-1].start()

    def tearDown(self):
        for patcher in self.patchers:
            patcher.stop()

    def _set_certificate_status(self, status):
        for cert_id in self.instance.cert_status:
            for key_type_id in KEY_TYPES:
                self.instance.cert_status[cert_id][key_type_id] = status

    @mock.patch('certcentral.certcentral.CertificateSigningRequest')
    @mock.patch.object(CertCentral, '_get_acme_session')
    @mock.patch.object(CertCentral, '_handle_pushed_csr')
    def test_new_certificate(self, handle_pushed_csr_mock, get_acme_session_mock, csr_mock):
        handle_pushed_csr_mock.return_value = CertificateStatus.VALID
        http_challenge_mock = mock.MagicMock()
        http_challenge_mock.file_name = 'mocked_challenged_file_name'
        get_acme_session_mock.return_value.push_csr.return_value = {
            ACMEChallengeType.HTTP01: [http_challenge_mock],
        }
        status = self.instance._new_certificate('test_certificate', 'ec-prime256v1')

        csr_mock.assert_called_once_with(common_name='certcentraltest.beta.wmflabs.org',
                                         private_key=self.ec_key_mock.return_value,
                                         sans=['certcentraltest.beta.wmflabs.org'])
        self.ec_key_mock.assert_called_once()
        expected_key_calls = [mock.call(),
                              mock.call().generate(**KEY_TYPES['ec-prime256v1']['params']),
                              mock.call().save(self.instance._get_path('test_certificate',
                                                                       'ec-prime256v1',
                                                                       public=False,
                                                                       kind='new'))]
        self.ec_key_mock.assert_has_calls(expected_key_calls)
        get_acme_session_mock.assert_called_once()
        acme_session_calls = [mock.call(self.instance.config.certificates['test_certificate']),
                              mock.call().push_csr(csr_mock.return_value)]
        get_acme_session_mock.assert_has_calls(acme_session_calls)
        http_challenge_mock_call = [mock.call.save(os.path.join(self.instance.challenges_path[ACMEChallengeType.HTTP01],
                                                                http_challenge_mock.file_name))]
        http_challenge_mock.assert_has_calls(http_challenge_mock_call)
        self.assertEqual(status, CertificateStatus.VALID)

    @mock.patch('certcentral.certcentral.CertificateSigningRequest')
    @mock.patch.object(CertCentral, '_trigger_dns_zone_update')
    @mock.patch.object(CertCentral, '_get_acme_session')
    @mock.patch.object(CertCentral, '_handle_pushed_csr')
    def test_new_certificate_dns01(self, handle_pushed_csr_mock, get_acme_session_mock, dns_zone_update_mock, csr_mock):
        handle_pushed_csr_mock.return_value = CertificateStatus.VALID
        dns_challenge_mock = mock.MagicMock()
        dns_challenge_mock.file_name = 'mocked_challenged_file_name'
        get_acme_session_mock.return_value.push_csr.return_value = {
            ACMEChallengeType.DNS01: [dns_challenge_mock],
        }
        status = self.instance._new_certificate('test_certificate_dns01', 'ec-prime256v1')

        csr_mock.assert_called_once_with(common_name='certcentraltest.beta.wmflabs.org',
                                         private_key=self.ec_key_mock.return_value,
                                         sans=['certcentraltest.beta.wmflabs.org'])
        self.ec_key_mock.assert_called_once()
        expected_key_calls = [mock.call(),
                              mock.call().generate(**KEY_TYPES['ec-prime256v1']['params']),
                              mock.call().save(self.instance._get_path('test_certificate_dns01',
                                                                       'ec-prime256v1',
                                                                       public=False,
                                                                       kind='new'))]
        self.ec_key_mock.assert_has_calls(expected_key_calls)
        get_acme_session_mock.assert_called_once()
        acme_session_calls = [mock.call(self.instance.config.certificates['test_certificate_dns01']),
                              mock.call().push_csr(csr_mock.return_value)]
        get_acme_session_mock.assert_has_calls(acme_session_calls)
        dns_zone_update_mock.assert_called_once()
        dns_challenge_mock_call = [mock.call.save(os.path.join(self.instance.challenges_path[ACMEChallengeType.DNS01],
                                                               dns_challenge_mock.file_name))]
        dns_challenge_mock.assert_has_calls(dns_challenge_mock_call)
        self.assertEqual(status, CertificateStatus.VALID)

    @mock.patch.object(PrivateKeyLoader, 'load')
    def test_handle_pushed_csr_pkey_error(self, pkey_loader_mock):
        for side_effect in [OSError, X509Error]:
            pkey_loader_mock.reset_mock()
            pkey_loader_mock.side_effect = side_effect
            status = self.instance._handle_pushed_csr('test_certificate', 'rsa-2048')
            self.assertEqual(status, CertificateStatus.SELF_SIGNED)

    @mock.patch.object(PrivateKeyLoader, 'load')
    @mock.patch('certcentral.certcentral.CertificateSigningRequest')
    @mock.patch.object(CertCentral, '_get_acme_session')
    @mock.patch.object(CertCentral, '_handle_validated_challenges')
    def test_handle_pushed_csr(self, handle_validated_challenges_mock,
                               get_acme_session_mock, csr_mock, pkey_loader_mock):
        handle_validated_challenges_mock.return_value = CertificateStatus.VALID
        challenge_mock = mock.MagicMock()
        challenge_mock.validate.return_value = ACMEChallengeValidation.VALID
        mocked_acme_session = mock.MagicMock()
        mocked_acme_session.challenges = {
            csr_mock.generate_csr_id.return_value: {
                ACMEChallengeType.HTTP01: [challenge_mock],
            }
        }
        get_acme_session_mock.return_value = mocked_acme_session
        status = self.instance._handle_pushed_csr('test_certificate', 'rsa-2048')
        self.assertEqual(status, CertificateStatus.VALID)

        pkey_loader_calls = [mock.call(self.instance._get_path('test_certificate', 'rsa-2048',
                                                               public=False, kind='new'))]
        pkey_loader_mock.assert_has_calls(pkey_loader_calls)

        csr_expected_calls = [mock.call.generate_csr_id(common_name='certcentraltest.beta.wmflabs.org',
                                                        public_key_pem=pkey_loader_mock.return_value.public_pem,
                                                        sans=['certcentraltest.beta.wmflabs.org'])]
        csr_mock.assert_has_calls(csr_expected_calls)

        acme_session_calls = [mock.call(self.instance.config.certificates['test_certificate'])]
        get_acme_session_mock.assert_has_calls(acme_session_calls)
        challenge_mock.assert_has_calls([mock.call.validate()])
        handle_validated_challenges_mock.assert_called_once_with('test_certificate', 'rsa-2048')

    @mock.patch.object(PrivateKeyLoader, 'load')
    def test_handle_validated_challenges_pkey_error(self, pkey_loader_mock):
        for side_effect in [OSError, X509Error]:
            pkey_loader_mock.reset_mock()
            pkey_loader_mock.side_effect = side_effect
            status = self.instance._handle_validated_challenges('test_certificate', 'rsa-2048')
            self.assertEqual(status, CertificateStatus.SELF_SIGNED)

    @mock.patch.object(PrivateKeyLoader, 'load')
    @mock.patch('certcentral.certcentral.CertificateSigningRequest')
    @mock.patch.object(CertCentral, '_get_acme_session')
    @mock.patch.object(CertCentral, '_handle_pushed_challenges')
    def test_handle_validated_challenges(self, handle_pushed_challenges_mock, get_acme_session_mock,
                                         csr_mock, pkey_loader_mock):
        handle_pushed_challenges_mock.return_value = CertificateStatus.VALID
        status = self.instance._handle_validated_challenges('test_certificate', 'rsa-2048')
        self.assertEqual(status, CertificateStatus.VALID)
        pkey_loader_calls = [mock.call(self.instance._get_path('test_certificate',
                                                               'rsa-2048', public=False, kind='new'))]
        pkey_loader_mock.assert_has_calls(pkey_loader_calls)
        csr_expected_calls = [mock.call.generate_csr_id(common_name='certcentraltest.beta.wmflabs.org',
                                                        public_key_pem=pkey_loader_mock.return_value.public_pem,
                                                        sans=['certcentraltest.beta.wmflabs.org'])]
        csr_mock.assert_has_calls(csr_expected_calls)
        get_acme_session_mock.assert_called_once()
        acme_session_calls = [mock.call(self.instance.config.certificates['test_certificate']),
                              mock.call().push_solved_challenges(csr_mock.generate_csr_id.return_value,
                                                                 challenge_type=ACMEChallengeType.HTTP01)]
        get_acme_session_mock.assert_has_calls(acme_session_calls)
        handle_pushed_challenges_mock.assert_called_once_with('test_certificate', 'rsa-2048')


    @mock.patch.object(PrivateKeyLoader, 'load')
    @mock.patch('certcentral.certcentral.CertificateSigningRequest')
    @mock.patch.object(CertCentral, '_get_acme_session')
    @mock.patch.object(CertCentral, '_handle_pushed_challenges')
    def test_handle_validated_challenges_solved_acme_error(self, handle_pushed_challenges_mock, get_acme_session_mock,
                                                           csr_mock, pkey_loader_mock):
        handle_pushed_challenges_mock.side_effect = ACMEError
        status = self.instance._handle_validated_challenges('test_certificate', 'rsa-2048')
        self.assertEqual(status, CertificateStatus.CHALLENGES_PUSHED)
        pkey_loader_calls = [mock.call(self.instance._get_path('test_certificate', 'rsa-2048',
                                                               public=False, kind='new'))]
        pkey_loader_mock.assert_has_calls(pkey_loader_calls)
        csr_expected_calls = [mock.call.generate_csr_id(common_name='certcentraltest.beta.wmflabs.org',
                                                        public_key_pem=pkey_loader_mock.return_value.public_pem,
                                                        sans=['certcentraltest.beta.wmflabs.org'])]
        csr_mock.assert_has_calls(csr_expected_calls)
        get_acme_session_mock.assert_called_once()
        acme_session_calls = [mock.call(self.instance.config.certificates['test_certificate']),
                              mock.call().push_solved_challenges(csr_mock.generate_csr_id.return_value, challenge_type=ACMEChallengeType.HTTP01)]
        get_acme_session_mock.assert_has_calls(acme_session_calls)
        handle_pushed_challenges_mock.assert_called_once_with('test_certificate', 'rsa-2048')

    @mock.patch.object(PrivateKeyLoader, 'load')
    def test_handle_pushed_challenges_pkey_error(self, pkey_loader_mock):
        for side_effect in [OSError, X509Error]:
            pkey_loader_mock.reset_mock()
            pkey_loader_mock.side_effect = side_effect
            status = self.instance._handle_pushed_challenges('test_certificate', 'rsa-2048')
            self.assertEqual(status, CertificateStatus.SELF_SIGNED)

    @mock.patch.object(PrivateKeyLoader, 'load')
    @mock.patch('certcentral.certcentral.CertificateSigningRequest')
    @mock.patch.object(CertCentral, '_get_acme_session')
    def test_handle_pushed_challenges_without_cert(self, get_acme_session_mock, csr_mock, pkey_loader_mock):
        get_acme_session_mock.return_value.get_certificate.return_value = None
        status = self.instance._handle_pushed_challenges('test_certificate', 'rsa-2048')
        self.assertEqual(status, CertificateStatus.CHALLENGES_PUSHED)
        pkey_loader_calls = [mock.call(self.instance._get_path('test_certificate', 'rsa-2048',
                                                               public=False, kind='new'))]
        pkey_loader_mock.assert_has_calls(pkey_loader_calls)
        get_acme_session_mock.assert_called_once()
        acme_session_calls = [mock.call(self.instance.config.certificates['test_certificate']),
                              mock.call().get_certificate(csr_mock.generate_csr_id.return_value)]
        get_acme_session_mock.assert_has_calls(acme_session_calls)

    @mock.patch.object(PrivateKeyLoader, 'load')
    @mock.patch('certcentral.certcentral.CertificateSigningRequest')
    @mock.patch.object(CertCentral, '_get_acme_session')
    @mock.patch.object(CertCentral, '_push_live_certificate')
    def test_handle_pushed_challenges(self, push_live_mock, get_acme_session_mock, csr_mock, pkey_loader_mock):
        push_live_mock.return_value = CertificateStatus.VALID
        status = self.instance._handle_pushed_challenges('test_certificate', 'rsa-2048')
        self.assertEqual(status, CertificateStatus.VALID)
        pkey_loader_calls = [mock.call(self.instance._get_path('test_certificate', 'rsa-2048',
                                                               public=False, kind='new'))]
        pkey_loader_mock.assert_has_calls(pkey_loader_calls)
        get_acme_session_mock.assert_called_once()
        acme_session_calls = [mock.call(self.instance.config.certificates['test_certificate']),
                              mock.call().get_certificate(csr_mock.generate_csr_id.return_value),
                              mock.call().get_certificate().save(self.instance._get_path('test_certificate',
                                                                                         'rsa-2048', public=True,
                                                                                         kind='new',
                                                                                         cert_type='full_chain'),
                                                                 mode=CertificateSaveMode.FULL_CHAIN)
        ]
        get_acme_session_mock.assert_has_calls(acme_session_calls)
        push_live_mock.assert_called_once_with('test_certificate', 'rsa-2048')


class CertCentralDetermineStatusTest(unittest.TestCase):
    @mock.patch('signal.signal')
    @mock.patch.object(CertCentral, 'sighup_handler')
    def setUp(self, signal_mock, sighup_handler_mock):
        self.instance = CertCentral()

        self.instance.config = CertCentralConfig(
            accounts=[{'id': '1945e767ad72a532ebca519242a801bf', 'directory': 'https://127.0.0.1:14000/dir'}],
            certificates={
                'test_certificate':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                    'challenge': 'http-01',
                },
            },
            default_account='1945e767ad72a532ebca519242a801bf',
            authorized_hosts={
                'test_certificate': ['localhost']
            },
            challenges={
                'dns-01': {
                    'validation_dns_servers': ['127.0.0.1'],
                    'sync_dns_servers': ['127.0.0.1'],
                }
            }
        )

    def _configure_load_return_value(self, status):
        return_value = mock.MagicMock()
        return_value.self_signed = False

        if status is CertificateStatus.SELF_SIGNED:
            return_value.self_signed = True
        elif status is CertificateStatus.EXPIRED:
            return_value.certificate.not_valid_after = datetime(1970, 1, 1)
        elif status is CertificateStatus.NEEDS_RENEWAL:
            return_value.certificate.not_valid_after = datetime.utcnow() + timedelta(days=10)
            return_value.needs_renew.return_value = True
        elif status is CertificateStatus.VALID:
            return_value.certificate.not_valid_after = datetime.utcnow() + timedelta(days=10)
            return_value.needs_renew.return_value = False

        return return_value

    @mock.patch.object(Certificate, 'load')
    def test_initial_status(self, load_mock):
        for test_status in [CertificateStatus.SELF_SIGNED,
                            CertificateStatus.EXPIRED,
                            CertificateStatus.NEEDS_RENEWAL,
                            CertificateStatus.VALID]:
            load_mock.reset_mock()
            load_mock.return_value = self._configure_load_return_value(test_status)

            status = self.instance._set_cert_status()
            load_calls = [mock.call(self.instance._get_path('test_certificate', 'ec-prime256v1',
                                                            public=True, kind='live')),
                          mock.call(self.instance._get_path('test_certificate', 'rsa-2048',
                                                            public=True, kind='live')),
                         ]
            load_mock.assert_has_calls(load_calls, any_order=True)
            self.assertEqual(len(status), len(self.instance.config.certificates))
            for certificate in self.instance.config.certificates:
                self.assertEqual(len(status[certificate]), len(KEY_TYPES))
                for cert_status in status[certificate].values():
                    self.assertEqual(cert_status, test_status)



class CertCentralIntegrationTest(BasePebbleIntegrationTest):
    @classmethod
    def setUpClass(cls, **kwargs):
        super().setUpClass(valid_challenges=True)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        base_path = self.temp_dir.name
        self.acme_account_base_path = os.path.join(base_path, CertCentral.accounts_path)
        for path in [CertCentral.accounts_path,
                     CertCentral.new_certs_path,
                     CertCentral.live_certs_path,
                     CertCentral.csrs_path,
                     CertCentral.confd_path,
                     CertCentral.dns_challenges_path,
                     CertCentral.http_challenges_path]:
            os.makedirs(os.path.join(base_path, path))

        HTTP01ChallengeHandler.challenges_path = os.path.join(base_path, CertCentral.http_challenges_path)
        BaseDNSRequestHandler.challenges_path = os.path.join(base_path, CertCentral.dns_challenges_path)
        proxy_host, proxy_port = self.proxy_server.server_address
        proxy_url = 'http://{}:{}'.format(proxy_host, proxy_port)
        dns_host, dns_port = self.dns_server.server_address
        self.patchers = [
            mock.patch.dict('certcentral.acme_requests.HTTP_VALIDATOR_PROXIES', {'http': proxy_url}),
            mock.patch('certcentral.acme_requests.DNS_SERVERS', [dns_host]),
            mock.patch('certcentral.acme_requests.DNS_PORT', dns_port),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self):
        self.temp_dir.cleanup()
        for patcher in self.patchers:
            patcher.stop()


    @mock.patch('certcentral.acme_requests.TLS_VERIFY', False)
    @mock.patch('signal.signal')
    @mock.patch.object(CertCentral, 'sighup_handler')
    def test_issue_new_certificate_http01(self, a, b):
        # Step 1 - create an ACME account
        account = ACMEAccount.create('tests-certcentral@wikimedia.org',
                                     base_path=self.acme_account_base_path,
                                     directory_url=DIRECTORY_URL)
        account.save()
        # Step 2 - Generate CertCentral config
        cert_central = CertCentral(base_path=self.temp_dir.name)
        cert_central.config = CertCentralConfig(
            accounts=[{'id': account.account_id, 'directory': DIRECTORY_URL}],
            certificates={
                'test_certificate':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                    'challenge': 'http-01',
                },
            },
            default_account=account.account_id,
            authorized_hosts={
                'test_certificate': ['localhost']
            },
            challenges={
                'dns-01': {
                    'validation_dns_servers': ['127.0.0.1'],
                    'sync_dns_servers': ['127.0.0.1'],
                }
            }
        )
        cert_central.cert_status = {'test_certificate': {
            'ec-prime256v1': CertificateStatus.INITIAL,
            'rsa-2048': CertificateStatus.INITIAL,
        }}

        # Step 3 - Generate self signed certificates
        cert_central.create_initial_certs()
        for cert_id in cert_central.cert_status:
            for key_type_id in KEY_TYPES:
                self.assertEqual(cert_central.cert_status[cert_id][key_type_id], CertificateStatus.SELF_SIGNED)
                cert = Certificate.load(cert_central._get_path(cert_id, key_type_id, public=True, kind='live'))
                self.assertTrue(cert.self_signed)

        # Step 4 - Request new certificates
        for cert_id in cert_central.cert_status:
            for key_type_id in KEY_TYPES:
                status = cert_central._new_certificate(cert_id, key_type_id)
                self.assertEqual(status, CertificateStatus.VALID)
                cert = Certificate.load(cert_central._get_path(cert_id, key_type_id, public=True, kind='live'))
                self.assertFalse(cert.self_signed)

    @mock.patch('certcentral.acme_requests.TLS_VERIFY', False)
    @mock.patch('signal.signal')
    @mock.patch.object(CertCentral, 'sighup_handler')
    def test_issue_new_certificate_dns01(self, a, b):
        # Step 1 - create an ACME account
        account = ACMEAccount.create('tests-certcentral@wikimedia.org',
                                     base_path=self.acme_account_base_path,
                                     directory_url=DIRECTORY_URL)
        account.save()
        # Step 2 - Generate CertCentral config
        cert_central = CertCentral(base_path=self.temp_dir.name)
        cert_central.config = CertCentralConfig(
            accounts=[{'id': account.account_id, 'directory': DIRECTORY_URL}],
            certificates={
                'test_certificate':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                    'challenge': 'dns-01',
                },
            },
            default_account=account.account_id,
            authorized_hosts={
                'test_certificate': ['localhost']
            },
            challenges={
                'dns-01': {
                    'validation_dns_servers': ['127.0.0.1'],
                    'sync_dns_servers': ['127.0.0.1'],
                }
            }
        )
        cert_central.cert_status = {'test_certificate': {
            'ec-prime256v1': CertificateStatus.INITIAL,
            'rsa-2048': CertificateStatus.INITIAL,
        }}

        # Step 3 - Generate self signed certificates
        cert_central.create_initial_certs()
        for cert_id in cert_central.cert_status:
            for key_type_id in KEY_TYPES:
                self.assertEqual(cert_central.cert_status[cert_id][key_type_id], CertificateStatus.SELF_SIGNED)
                cert = Certificate.load(cert_central._get_path(cert_id, key_type_id, public=True, kind='live'))
                self.assertTrue(cert.self_signed)

        # Step 4 - Request new certificates
        for cert_id in cert_central.cert_status:
            for key_type_id in KEY_TYPES:
                status = cert_central._new_certificate(cert_id, key_type_id)
                self.assertEqual(status, CertificateStatus.VALID)
                cert = Certificate.load(cert_central._get_path(cert_id, key_type_id, public=True, kind='live'))
                self.assertFalse(cert.self_signed)

    @mock.patch('certcentral.acme_requests.TLS_VERIFY', False)
    @mock.patch('signal.signal')
    @mock.patch.object(CertCentral, 'sighup_handler')
    def test_issue_new_certificate_force_validation_failure(self, a, b):
        # Step 1 - create an ACME account
        account = ACMEAccount.create('tests-certcentral@wikimedia.org',
                                     base_path=self.acme_account_base_path,
                                     directory_url=DIRECTORY_URL)
        account.save()
        # Step 2 - Generate CertCentral config
        cert_central = CertCentral(base_path=self.temp_dir.name)
        cert_central.config = CertCentralConfig(
            accounts=[{'id': account.account_id, 'directory': DIRECTORY_URL}],
            certificates={
                'test_certificate':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                    'challenge': 'http-01',
                },
            },
            default_account=account.account_id,
            authorized_hosts={
                'test_certificate': ['localhost']
            },
            challenges={
                'dns-01': {
                    'validation_dns_servers': ['127.0.0.1'],
                    'sync_dns_servers': ['127.0.0.1'],
                }
            }
        )
        cert_central.cert_status = {'test_certificate': {
            'ec-prime256v1': CertificateStatus.INITIAL,
            'rsa-2048': CertificateStatus.INITIAL,
        }}

        # Step 3 - Generate self signed certificates
        cert_central.create_initial_certs()
        for cert_id in cert_central.cert_status:
            for key_type_id in KEY_TYPES:
                self.assertEqual(cert_central.cert_status[cert_id][key_type_id], CertificateStatus.SELF_SIGNED)
                cert = Certificate.load(cert_central._get_path(cert_id, key_type_id, public=True, kind='live'))
                self.assertTrue(cert.self_signed)

        # Step 4 - Request new certificates setting a wrong challenge location
        # to force a challenge validation issue
        with tempfile.TemporaryDirectory() as fake_challenge_dir:
            valid_challenge_path = cert_central.challenges_path[ACMEChallengeType.HTTP01]
            cert_central.challenges_path[ACMEChallengeType.HTTP01] = fake_challenge_dir
            for cert_id in cert_central.cert_status:
                for key_type_id in KEY_TYPES:
                    status = cert_central._new_certificate(cert_id, key_type_id)
                    self.assertEqual(status, CertificateStatus.CSR_PUSHED)

            cert_central.challenges_path[ACMEChallengeType.HTTP01] = valid_challenge_path
            # Copy the challenges to the correct challenge path
            for challenge_file in os.listdir(fake_challenge_dir):
                challenge_file_path = os.path.join(fake_challenge_dir, challenge_file)
                shutil.copy2(challenge_file_path, valid_challenge_path)

        # Step 5 - Resume the process
        for cert_id in cert_central.cert_status:
            for key_type_id in KEY_TYPES:
                status = cert_central._handle_pushed_csr(cert_id, key_type_id)
                self.assertEqual(status, CertificateStatus.VALID)
                cert = Certificate.load(cert_central._get_path(cert_id, key_type_id, public=True, kind='live'))
                self.assertFalse(cert.self_signed)

    @mock.patch('certcentral.acme_requests.TLS_VERIFY', False)
    @mock.patch('signal.signal')
    @mock.patch.object(CertCentral, 'sighup_handler')
    @mock.patch('certcentral.certcentral.sleep', side_effect=InfiniteLoopBreaker)
    def test_certificate_management(self, a, b, c):
        # Step 1 - create an ACME account
        account = ACMEAccount.create('tests-certcentral@wikimedia.org',
                                     base_path=self.acme_account_base_path,
                                     directory_url=DIRECTORY_URL)
        account.save()
        # Step 2 - Generate CertCentral config
        cert_central = CertCentral(base_path=self.temp_dir.name)
        cert_central.config = CertCentralConfig(
            accounts=[{'id': account.account_id, 'directory': DIRECTORY_URL}],
            certificates={
                'test_certificate':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                    'challenge': 'http-01',
                },
            },
            default_account=account.account_id,
            authorized_hosts={
                'test_certificate': ['localhost']
            },
            challenges={
                'dns-01': {
                    'validation_dns_servers': ['127.0.0.1'],
                    'sync_dns_servers': ['127.0.0.1'],
                }
            }
        )
        cert_central.cert_status = {'test_certificate': {
            'ec-prime256v1': CertificateStatus.INITIAL,
            'rsa-2048': CertificateStatus.INITIAL,
        }}

        # Step 3 - Generate self signed certificates
        cert_central.create_initial_certs()

        # Step 4 - run one iteration of certificate management
        with self.assertRaises(InfiniteLoopBreaker):
            cert_central.certificate_management()
        for cert_id in cert_central.cert_status:
            for key_type_id in KEY_TYPES:
                self.assertEqual(cert_central.cert_status[cert_id][key_type_id], CertificateStatus.VALID)
                cert = Certificate.load(cert_central._get_path(cert_id, key_type_id, public=True, kind='live'))
                self.assertFalse(cert.self_signed)
