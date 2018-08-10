import os
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta

import mock
from cryptography.hazmat.primitives.asymmetric import ec

from acme_requests import ACMEAccount, ACMEChallengeType, ACMEError
from certcentral import (KEY_TYPES, CertCentral, CertCentralConfig,
                         CertificateStatus)
from x509 import Certificate, ECPrivateKey, PrivateKeyLoader, X509Error

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


class CertCentralTest(unittest.TestCase):
    @mock.patch('signal.signal')
    @mock.patch.object(CertCentral, 'sighup_handler')
    def setUp(self, sighup_handler_mock, signal_mock):
        self.instance = CertCentral()

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

    @mock.patch('certcentral.SelfSignedCertificate')
    def test_create_initial_tests(self, self_signed_cert_mock):
        self.instance.config = CertCentralConfig(
            accounts=[{'id': '1945e767ad72a532ebca519242a801bf', 'directory': 'https://127.0.0.1:14000/dir'}],
            certificates={
                'test_certificate':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                },
            },
            default_account='1945e767ad72a532ebca519242a801bf',
            authorized_hosts={
                'test_certificate': ['localhost']
            }
        )

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

        with mock.patch.dict('certcentral.KEY_TYPES', {'ec-prime256v1': ec_key, 'rsa-2048': rsa_key}):
            self.instance.create_initial_certs()

        rsa_key_mock.assert_called_once()
        expected_key_calls = [mock.call(),
                              mock.call().generate(**KEY_TYPES['rsa-2048']['params']),
                              mock.call().save(self.instance._get_live_path('test_certificate',
                                                                            'rsa-2048',
                                                                            public=False))]
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
        self_signed_cert_mock.assert_has_calls([mock.call().save(self.instance._get_live_path('test_certificate', 'rsa-2048', public=True))])

    @mock.patch.object(ACMEAccount, 'load')
    @mock.patch('certcentral.ACMERequests')
    def test_get_acme_session(self, requests_mock, account_load_mock):
        self.instance.config = CertCentralConfig(
            accounts=[{'id': '1945e767ad72a532ebca519242a801bf', 'directory': 'https://127.0.0.1:14000/dir'}],
            certificates={
                'test_certificate':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                },
            },
            default_account='1945e767ad72a532ebca519242a801bf',
            authorized_hosts={
                'test_certificate': ['localhost']
            }
        )

        session = self.instance._get_acme_session({
            'CN': 'certcentraltest.beta.wmflabs.org',
            'SNI': ['certcentraltest.beta.wmflabs.org'],
        })

        account_load_mock.assert_called_once_with('1945e767ad72a532ebca519242a801bf',
                                                  directory_url='https://127.0.0.1:14000/dir')
        requests_mock.assert_called_once_with(account_load_mock.return_value)
        self.assertEqual(session, requests_mock.return_value)

    def test_certificate_management(self):
        self.instance.config = CertCentralConfig(
            accounts=[{'id': '1945e767ad72a532ebca519242a801bf', 'directory': 'https://127.0.0.1:14000/dir'}],
            certificates={
                'test_certificate':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                },
            },
            default_account='1945e767ad72a532ebca519242a801bf',
            authorized_hosts={
                'test_certificate': ['localhost']
            }
        )

        for status in [CertificateStatus.SELF_SIGNED,
                       CertificateStatus.NEEDS_RENEWAL,
                       CertificateStatus.EXPIRED]:
            self.instance.cert_status = {'test_certificate': {
                'ec-prime256v1': status,
                'rsa-2048': status,
            }}
            with mock.patch('time.sleep', side_effect=InfiniteLoopBreaker) as sleep_mock:
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

            with mock.patch('time.sleep', side_effect=InfiniteLoopBreaker) as sleep_mock:
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

            with mock.patch('time.sleep', side_effect=InfiniteLoopBreaker) as sleep_mock:
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
    def setUp(self, signal_mock, sighup_handler_mock):
        self.instance = CertCentral()

        self.instance.config = CertCentralConfig(
            accounts=[{'id': '1945e767ad72a532ebca519242a801bf', 'directory': 'https://127.0.0.1:14000/dir'}],
            certificates={
                'test_certificate':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                },
            },
            default_account='1945e767ad72a532ebca519242a801bf',
            authorized_hosts={
                'test_certificate': ['localhost']
            }
        )

        self.patchers = []

        self.ec_key_mock = mock.MagicMock()
        self.rsa_key_mock = mock.MagicMock()
        ec_key = deepcopy(KEY_TYPES['ec-prime256v1'])
        ec_key['class'] = self.ec_key_mock
        rsa_key = deepcopy(KEY_TYPES['rsa-2048'])
        rsa_key['class'] = self.rsa_key_mock

        self.patchers.append(mock.patch.dict('certcentral.KEY_TYPES', {'ec-prime256v1': ec_key, 'rsa-2048': rsa_key}))
        self.patchers[-1].start()

    def tearDown(self):
        for patcher in self.patchers:
            patcher.stop()

    def _set_certificate_status(self, status):
        for cert_id in self.instance.cert_status:
            for key_type_id in KEY_TYPES:
                self.instance.cert_status[cert_id][key_type_id] = status

    @mock.patch('certcentral.CertificateSigningRequest')
    @mock.patch.object(CertCentral, '_get_acme_session')
    @mock.patch.object(CertCentral, '_handle_pushed_csr')
    @mock.patch.object(CertCentral, '_handle_pushed_challenges')
    def test_new_certificate(self, handle_pushed_challenges_mock, handle_pushed_csr_mock, get_acme_session_mock, csr_mock):

        handle_pushed_csr_mock.return_value = CertificateStatus.CHALLENGES_PUSHED
        handle_pushed_challenges_mock.return_value = CertificateStatus.VALID
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
                              mock.call().save(self.instance._get_live_path('test_certificate',
                                                                            'ec-prime256v1',
                                                                            public=False))]
        self.ec_key_mock.assert_has_calls(expected_key_calls)
        get_acme_session_mock.assert_called_once()
        acme_session_calls = [mock.call(self.instance.config.certificates['test_certificate']),
                              mock.call().push_csr(csr_mock.return_value)]
        get_acme_session_mock.assert_has_calls(acme_session_calls)
        http_challenge_mock.assert_has_calls([mock.call.save(os.path.join(self.instance.http_challenges_path,
                                                                            http_challenge_mock.file_name))])
        handle_pushed_csr_mock.assert_called_once_with('test_certificate', 'ec-prime256v1')
        handle_pushed_challenges_mock.assert_called_once_with('test_certificate', 'ec-prime256v1')
        self.assertEqual(status, CertificateStatus.VALID)

    @mock.patch.object(PrivateKeyLoader, 'load')
    def test_handle_pushed_csr_pkey_error(self, pkey_loader_mock):
        for side_effect in [OSError, X509Error]:
            pkey_loader_mock.reset_mock()
            pkey_loader_mock.side_effect = side_effect
            status = self.instance._handle_pushed_csr('test_certificate', 'rsa-2048')
            self.assertEqual(status, CertificateStatus.SELF_SIGNED)

    @mock.patch.object(PrivateKeyLoader, 'load')
    @mock.patch('certcentral.CertificateSigningRequest')
    @mock.patch.object(CertCentral, '_get_acme_session')
    @mock.patch.object(CertCentral, '_handle_pushed_challenges')
    def test_handle_pushed_csr(self, handle_pushed_challenges_mock, get_acme_session_mock, csr_mock, pkey_loader_mock):
        handle_pushed_challenges_mock.return_value = CertificateStatus.VALID
        status = self.instance._handle_pushed_csr('test_certificate', 'rsa-2048')
        self.assertEqual(status, CertificateStatus.VALID)
        pkey_loader_calls = [mock.call(self.instance._get_live_path('test_certificate', 'rsa-2048', public=False))]
        pkey_loader_mock.assert_has_calls(pkey_loader_calls)
        csr_expected_calls = [mock.call.generate_csr_id(common_name='certcentraltest.beta.wmflabs.org', public_key_pem=pkey_loader_mock.return_value.public_pem, sans=['certcentraltest.beta.wmflabs.org'])]
        csr_mock.assert_has_calls(csr_expected_calls)
        get_acme_session_mock.assert_called_once()
        acme_session_calls = [mock.call(self.instance.config.certificates['test_certificate']),
                              mock.call().push_solved_challenges(csr_mock.generate_csr_id.return_value, challenge_type=ACMEChallengeType.HTTP01)]
        get_acme_session_mock.assert_has_calls(acme_session_calls)
        handle_pushed_challenges_mock.assert_called_once_with('test_certificate', 'rsa-2048')


    @mock.patch.object(PrivateKeyLoader, 'load')
    @mock.patch('certcentral.CertificateSigningRequest')
    @mock.patch.object(CertCentral, '_get_acme_session')
    @mock.patch.object(CertCentral, '_handle_pushed_challenges')
    def test_handle_pushed_csr_solved_acme_error(self, handle_pushed_challenges_mock, get_acme_session_mock, csr_mock, pkey_loader_mock):
        handle_pushed_challenges_mock.side_effect = ACMEError
        status = self.instance._handle_pushed_csr('test_certificate', 'rsa-2048')
        self.assertEqual(status, CertificateStatus.CHALLENGES_PUSHED)
        pkey_loader_calls = [mock.call(self.instance._get_live_path('test_certificate', 'rsa-2048', public=False))]
        pkey_loader_mock.assert_has_calls(pkey_loader_calls)
        csr_expected_calls = [mock.call.generate_csr_id(common_name='certcentraltest.beta.wmflabs.org', public_key_pem=pkey_loader_mock.return_value.public_pem, sans=['certcentraltest.beta.wmflabs.org'])]
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
    @mock.patch('certcentral.CertificateSigningRequest')
    @mock.patch.object(CertCentral, '_get_acme_session')
    def test_handle_pushed_challenges_without_cert(self, get_acme_session_mock, csr_mock, pkey_loader_mock):
        get_acme_session_mock.return_value.get_certificate.return_value = None
        status = self.instance._handle_pushed_challenges('test_certificate', 'rsa-2048')
        self.assertEqual(status, CertificateStatus.CHALLENGES_PUSHED)
        pkey_loader_calls = [mock.call(self.instance._get_live_path('test_certificate', 'rsa-2048', public=False))]
        pkey_loader_mock.assert_has_calls(pkey_loader_calls)
        get_acme_session_mock.assert_called_once()
        acme_session_calls = [mock.call(self.instance.config.certificates['test_certificate']),
                              mock.call().get_certificate(csr_mock.generate_csr_id.return_value)]
        get_acme_session_mock.assert_has_calls(acme_session_calls)

    @mock.patch.object(PrivateKeyLoader, 'load')
    @mock.patch('certcentral.CertificateSigningRequest')
    @mock.patch.object(CertCentral, '_get_acme_session')
    def test_handle_pushed_challenges(self, get_acme_session_mock, csr_mock, pkey_loader_mock):
        status = self.instance._handle_pushed_challenges('test_certificate', 'rsa-2048')
        self.assertEqual(status, CertificateStatus.VALID)
        pkey_loader_calls = [mock.call(self.instance._get_live_path('test_certificate', 'rsa-2048', public=False))]
        pkey_loader_mock.assert_has_calls(pkey_loader_calls)
        get_acme_session_mock.assert_called_once()
        acme_session_calls = [mock.call(self.instance.config.certificates['test_certificate']),
                              mock.call().get_certificate(csr_mock.generate_csr_id.return_value),
                              mock.call().get_certificate().save(self.instance._get_live_path('test_certificate',
                                                                                              'rsa-2048', public=True))
        ]
        get_acme_session_mock.assert_has_calls(acme_session_calls)


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
                },
            },
            default_account='1945e767ad72a532ebca519242a801bf',
            authorized_hosts={
                'test_certificate': ['localhost']
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
            load_calls = [mock.call(self.instance._get_live_path('test_certificate', 'ec-prime256v1', public=True)),
                          mock.call(self.instance._get_live_path('test_certificate', 'rsa-2048', public=True)),
                         ]
            load_mock.assert_has_calls(load_calls, any_order=True)
            self.assertEqual(len(status), len(self.instance.config.certificates))
            for certificate in self.instance.config.certificates:
                self.assertEqual(len(status[certificate]), len(KEY_TYPES))
                for cert_status in status[certificate].values():
                    self.assertEqual(cert_status, test_status)
