import hashlib
import itertools
import os
import tempfile
import unittest
from unittest import mock

import dns
import requests_mock
from cryptography import x509 as crypto_x509
from cryptography.x509.oid import ExtensionOID, NameOID

from acme_chief.acme_requests import (DEFAULT_DNS01_VALIDATION_TIMEOUT,
                                      ACMEAccount, ACMEAccountFiles,
                                      ACMEChallengeNotValidatedError,
                                      ACMEChallengeType,
                                      ACMEChallengeValidation, ACMERequests,
                                      ACMEValidator,
                                      DNS01ACMEChallenge, HTTP01ACMEChallenge,
                                      DNS01ACMEValidator, HTTP01ACMEValidator)
from acme_chief.x509 import (CertificateSigningRequest, ECPrivateKey,
                             RSAPrivateKey)
from tests.test_pebble import BasePebbleIntegrationTest

DIRECTORY_URL = 'https://127.0.0.1:14000/dir'

DNS_PORT = 5353


class ACMEAccountTest(unittest.TestCase):
    def test_basic_init(self):
        account = ACMEAccount(base_path='/non/existent', directory_url=DIRECTORY_URL)
        self.assertEqual(account.base_path, '/non/existent')
        self.assertEqual(account.directory_url, DIRECTORY_URL)
        self.assertIsInstance(account.key, RSAPrivateKey)
        self.assertIsNone(account.regr)
        self.assertEqual(account.account_id, hashlib.md5(account.key.public_pem).hexdigest())


class ACMEChallengeTest(unittest.TestCase):
    def test_save(self):
        challenges = [HTTP01ACMEChallenge(hostname='tests.wmflabs.org',
                                          path='/.well-known/acme-challenge/BMHfMfFy0DtWYRwjxMFFSkmYZS5azT58-4YDrWfW_l4',
                                          validation='BMHfMfFy0DtWYRwjxMFFSkmYZS5azT58-4YDrWfW_l4.xnhzweFE-KO1EIuyHhY7iFw7ROdIN_uPCXG2tYK-Sv8'),
                      DNS01ACMEChallenge(validation_domain_name='_acme-challenge.tests.wmflab.org',
                                         validation="fake_validation"),
        ]
        for challenge in challenges:
            with tempfile.TemporaryDirectory() as temp_dir:
                challenge_path = os.path.join(temp_dir, challenge.file_name)
                challenge.save(os.path.join(challenge_path))

                with open(challenge_path, 'r') as challenge_file:
                    validation = challenge_file.read()
                    self.assertEqual(validation, challenge.validation)

    def test_validate_http(self):
        challenge = HTTP01ACMEChallenge(hostname='tests.wmflabs.org',
                                        path='/.well-known/acme-challenge/fake_validation',
                                        validation='fake_validation')

        url = 'http://{}:80{}'.format(challenge.hostname, challenge.path)

        test_cases = [
            {
                'name': 'OK',
                'expected_result': ACMEChallengeValidation.VALID,
                'mocker_kwargs': {
                    'text': challenge.validation,
                },
            },
            {
                'name': 'Invalid challenge content',
                'expected_result': ACMEChallengeValidation.INVALID,
                'mocker_kwargs': {
                    'text': "I don't know how to solve the challenge",
                },
            },
            {
                'name': 'challenge file not found (404)',
                'expected_result': ACMEChallengeValidation.INVALID,
                'mocker_kwargs': {
                    'text': "Not found",
                    'status_code': 404,
                },
            },
        ]

        for test_case in test_cases:
            with requests_mock.Mocker() as req_mock:
                req_mock.get(url, **test_case['mocker_kwargs'])
                result = challenge.validate()
                self.assertEqual(result, test_case['expected_result'], test_case['name'])

    @mock.patch('acme_chief.acme_requests.Resolver')
    def test_validate_dns(self, resolver_mock):
        challenge = DNS01ACMEChallenge(validation_domain_name='_acme-challenge.tests.wmflab.org',
                                       validation="fake_validation")
        dns_servers_cases = (
            (None,),
            ('127.0.0.1',),
            ('127.0.0.1', '127.0.0.2'),
        )

        for dns_servers in dns_servers_cases:
            for validation_result in (ACMEChallengeValidation.VALID, ACMEChallengeValidation.INVALID):
                with self.subTest(dns_servers=dns_servers, validation_result=validation_result):
                    resolver_mock.reset_mock()
                    resolver_instance_mock = resolver_mock.return_value
                    if validation_result is ACMEChallengeValidation.VALID:
                        resolver_instance_mock.txt_query.return_value = [challenge.validation]
                    else:
                        resolver_instance_mock.txt_query.return_value = ['foo']

                    resolver_mock.resolve_dns_servers.return_value = dns_servers
                    result = challenge.validate(dns_servers=dns_servers, dns_port=DNS_PORT)
                    self.assertEqual(len(dns_servers), len(resolver_instance_mock.txt_query.mock_calls))
                    resolver_mock_calls = []
                    txt_query_calls = []
                    for dns_server in dns_servers:
                        resolver_mock_calls.append(mock.call(nameservers=(dns_server,),
                                                             port=DNS_PORT,
                                                             timeout=DEFAULT_DNS01_VALIDATION_TIMEOUT))
                        txt_query_calls.append(mock.call(challenge.validation_domain_name))
                    resolver_mock.assert_has_calls(resolver_mock_calls, any_order=True)
                    resolver_instance_mock.txt_query.assert_has_calls(txt_query_calls)
                    resolver_mock.resolve_dns_servers.assert_called_once_with(dns_servers)
                    self.assertEqual(result, validation_result)

    @mock.patch.object(dns.resolver.Resolver, 'query')
    def test_validate_dns_errors(self, query_mock):
        challenge = DNS01ACMEChallenge(validation_domain_name='_acme-challenge.tests.wmflabs.org',
                                       validation='foobar')
        test_cases = [
            {
                'name': 'NXDOMAIN',
                'side_effect': dns.resolver.NXDOMAIN,
                'result': ACMEChallengeValidation.INVALID,
            },
            {
                'name': 'YXDOMAIN',
                'side_effect': dns.resolver.YXDOMAIN,
                'result': ACMEChallengeValidation.INVALID,
            },
            {
                'name': 'No anwser',
                'side_effect': dns.resolver.NoAnswer,
                'result': ACMEChallengeValidation.INVALID,
            },
            {
                'name': 'Timeout',
                'side_effect': dns.exception.Timeout,
                'result': ACMEChallengeValidation.UNKNOWN,
            },
            {
                'name': 'No Nameservers',
                'side_effect': dns.resolver.NoNameservers,
                'result': ACMEChallengeValidation.UNKNOWN,
            },
        ]

        for test_case in test_cases:
            query_mock.reset()
            query_mock.side_effect = test_case['side_effect']
            result = challenge.validate(dns_port=DNS_PORT)
            self.assertEqual(result, test_case['result'], test_case['name'])


class ACMEIntegrationTests(BasePebbleIntegrationTest):
    def test_account_persistence(self):
        with tempfile.TemporaryDirectory() as base_path:
            with mock.patch('acme_chief.acme_requests.TLS_VERIFY', False):
                account = ACMEAccount.create('test-persistence@wikimedia.org',
                                             base_path=base_path,
                                             directory_url=DIRECTORY_URL)
            account.save()
            account_id = account.account_id

            for account_file in ACMEAccountFiles:
                file_path = os.path.join(base_path, account_id, account_file.value)
                self.assertTrue(os.path.isfile(file_path))

            with mock.patch('acme_chief.acme_requests.TLS_VERIFY', False):
                load_account = ACMEAccount.load(account_id, base_path=base_path, directory_url=DIRECTORY_URL)
                self.assertIsInstance(load_account, ACMEAccount)
                self.assertIsInstance(ACMERequests(load_account), ACMERequests)

    def test_full_workflow_dns_challenge(self):
        """Expects pebble to be invoked with PEBBLE_VA_ALWAYS_VALID=1"""
        with mock.patch('acme_chief.acme_requests.TLS_VERIFY', False):
            account = ACMEAccount.create('tests-dns@wikimedia.org', directory_url=DIRECTORY_URL)
            session = ACMERequests(account)
        self.assertIsNotNone(account.regr)

        key = RSAPrivateKey()
        key.generate()
        csr = CertificateSigningRequest(
            private_key=key,
            common_name="tests.wmflabs.org",
            sans=[
                "tests.wmflabs.org",
                "*.tests.wmflabs.org",
            ],
        )

        challenges = session.push_csr(csr)
        self.assertIn(ACMEChallengeType.DNS01, challenges)
        self.assertNotIn(ACMEChallengeType.HTTP01, challenges)

        session.push_solved_challenges(csr.csr_id)
        # pebble adds a random delay on validations, so we need to pull until we
        # get the certificate
        while True:
            self.assertTrue(session.orders)
            try:
                session.finalize_order(csr.csr_id)
                certificate = session.get_certificate(csr.csr_id)
                break
            except ACMEChallengeNotValidatedError:
                pass
        self.assertFalse(session.orders)
        self.assertFalse(certificate.needs_renew())
        self.assertFalse(certificate.self_signed)
        self.assertEqual(len(certificate.chain), 2)
        sans = certificate.certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertEqual(sans.value.get_values_for_type(crypto_x509.DNSName),
                         ['tests.wmflabs.org', '*.tests.wmflabs.org'])

        # if everything goes as expected this shouldn't raise an exception
        session.revoke_certificate(certificate)

    def test_full_workflow_http_challenge(self):
        """Expects pebble to be invoked with PEBBLE_VA_ALWAYS_VALID=1"""
        with mock.patch('acme_chief.acme_requests.TLS_VERIFY', False):
            account = ACMEAccount.create('tests-http@wikimedia.org', directory_url=DIRECTORY_URL)
            session = ACMERequests(account)
        self.assertIsNotNone(account.regr)

        key = RSAPrivateKey()
        key.generate()
        csr = CertificateSigningRequest(
            private_key=key,
            common_name="tests.wmflabs.org",
            sans=[
                "tests.wmflabs.org",
            ],
        )

        challenges = session.push_csr(csr)
        self.assertIn(ACMEChallengeType.DNS01, challenges)
        self.assertIn(ACMEChallengeType.HTTP01, challenges)

        session.push_solved_challenges(csr.csr_id, ACMEChallengeType.HTTP01)
        while True:
            self.assertTrue(session.orders)
            try:
                session.finalize_order(csr.csr_id)
                certificate = session.get_certificate(csr.csr_id)
                break
            except ACMEChallengeNotValidatedError:
                pass
        self.assertFalse(session.orders)
        self.assertFalse(certificate.needs_renew())
        self.assertFalse(certificate.self_signed)
        self.assertEqual(len(certificate.chain), 2)
        sans = certificate.certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertEqual(sans.value.get_values_for_type(crypto_x509.DNSName), ['tests.wmflabs.org'])

    def test_full_workflow_ec_certificate(self):
        """Expects pebble to be invoked with PEBBLE_VA_ALWAYS_VALID=1"""
        with mock.patch('acme_chief.acme_requests.TLS_VERIFY', False):
            account = ACMEAccount.create('tests-ec@wikimedia.org', directory_url=DIRECTORY_URL)
            session = ACMERequests(account)
        self.assertIsNotNone(account.regr)

        key = ECPrivateKey()
        key.generate()

        csr = CertificateSigningRequest(
            private_key=key,
            common_name="tests.wmflabs.org",
            sans=[
                "tests.wmflabs.org",
                "*.tests.wmflabs.org",
            ],
        )

        session.push_csr(csr)
        challenges = session.push_csr(csr)
        self.assertIn(ACMEChallengeType.DNS01, challenges)
        self.assertNotIn(ACMEChallengeType.HTTP01, challenges)

        session.push_solved_challenges(csr.csr_id)
        while True:
            self.assertTrue(session.orders)
            try:
                session.finalize_order(csr.csr_id)
                certificate = session.get_certificate(csr.csr_id)
                break
            except ACMEChallengeNotValidatedError:
                pass
        self.assertFalse(session.orders)
        self.assertFalse(certificate.needs_renew())
        self.assertFalse(certificate.self_signed)
        self.assertEqual(len(certificate.chain), 2)
        sans = certificate.certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertEqual(sans.value.get_values_for_type(crypto_x509.DNSName),
                         ['tests.wmflabs.org', '*.tests.wmflabs.org'])


class ACMEValidatorTest(unittest.TestCase):
    @mock.patch('acme_chief.dns.Resolver.get_record')
    def test_caa_validator(self, get_record_mock):
        test_cases = (
            {
                'common_name': 'testdomain.org',
                'caa_records': ('0 iodef "mailto:dns-admin@wikimedia.org"',),
                'result': True,
            },
            {
                'common_name': '*.testdomain.org',
                'caa_records': ('0 iodef "mailto:dns-admin@wikimedia.org"',),
                'result': True,
            },
            {
                'common_name': 'testdomain.org',
                'caa_records': ('0 issue ";"',),
                'result': False,
            },
            {
                'common_name': '*.testdomain.org',
                'caa_records': ('0 issue ";"',),
                'result': False,
            },
            {
                'common_name': 'testdomain.org',
                'caa_records':
                (
                    '0 issue "letsencrypt.org"',
                    '0 issue "fakeca.org"',
                    '0 iodef "mailto:dns-admin@wikimedia.org"',
                ),
                'result': True,
            },
            {
                'common_name': 'testdomain.org',
                'caa_records':
                (
                    '0 issue "letsencrypt.org"',
                    '0 issuewild "fakeca.org"',
                    '0 iodef "mailto:dns-admin@wikimedia.org"',
                ),
                'result': False,
            },
            {
                'common_name': '*.testdomain.org',
                'caa_records':
                (
                    '0 issue "letsencrypt.org"',
                    '0 issuewild "fakeca.org"',
                    '0 iodef "mailto:dns-admin@wikimedia.org"',
                ),
                'result': True,
            },
            {
                'common_name': '*.testdomain.org',
                'caa_records':
                (
                    '0 issue "fakeca.org"',
                    '0 issuewild ";"',
                    '0 iodef "mailto:dns-admin@wikimedia.org"',
                ),
                'result': False,
            },
            {
                'common_name': 'testdomain.org',
                'caa_records':
                (
                    '0 issue "letsencrypt.org"',
                    '0 iodef "mailto:dns-admin@wikimedia.org"',
                ),
                'result': False,
            },
            {
                'common_name': 'testdomain.org',
                'caa_records':
                (
                    '0 issue "letsencrypt.org"',
                    '0 issue ";"',
                    '0 iodef "mailto:dns-admin@wikimedia.org"',
                ),
                'result': False,
            },
        )
        validator = ACMEValidator(issuing_ca='fakeca.org')
        for test_case in test_cases:
            with self.subTest(common_name=test_case['common_name'],
                              caa_records=test_case['caa_records'], result=test_case['result']):
                get_record_mock.reset_mock()
                get_record_mock.return_value = test_case['caa_records']
                result = validator.validate(test_case['common_name'])
                self.assertEqual(result, test_case['result'])
                get_record_mock.assert_called_once_with('testdomain.org', 'CAA')


class DNS01ACMEValidatorTests(unittest.TestCase):
    @mock.patch('acme_chief.dns.Resolver.get_record')
    def test_ns_validator(self, get_record_mock):
        test_cases = (
            {
                'ns_records': ('ns2.wikimedia.org',),
                'result': False,
            },
            {
                'ns_records': ('ns0.wikimedia.org', 'ns1.wikimedia.org',),
                'result': True,
            },
            {
                'ns_records': ('ns0.wikimedia.org', 'ns1.wikimedia.org', 'ns2.wikimedia.org'),
                'result': False,
            }
        )
        dns01validator = DNS01ACMEValidator('fakeca.org', ('ns0.wikimedia.org', 'ns1.wikimedia.org'))

        for test_case in test_cases:
            with self.subTest(ns_records=test_case['ns_records'], result=test_case['result'], wildcard=False):
                get_record_mock.reset_mock()
                get_record_mock.return_value = test_case['ns_records']
                result = dns01validator._validate_ns_record('www.testdomain.org')
                self.assertEqual(result, test_case['result'])
                get_record_mock.assert_called_once_with('www.testdomain.org', 'NS')

    @mock.patch('acme_chief.acme_requests.DNS01ACMEValidator._validate_caa_record')
    @mock.patch('acme_chief.acme_requests.DNS01ACMEValidator._validate_ns_record')
    def test_validate(self, validate_ns_mock, validate_caa_mock):
        for result in (True, False):
            with self.subTest(result=result):
                validate_ns_mock.reset_mock()
                validate_caa_mock.reset_mock()
                validate_caa_mock.return_value = True
                validate_ns_mock.return_value = result
                dns01validator = DNS01ACMEValidator('fakeca.org', ('ns0.wikimedia.org', 'ns1.wikimedia.org'))
                ret = dns01validator.validate('testdomain.org')
                self.assertEqual(ret, result)
                validate_caa_mock.assert_called_once_with('testdomain.org')
                validate_ns_mock.assert_called_once_with('testdomain.org')
