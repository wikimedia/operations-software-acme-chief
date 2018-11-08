import hashlib
import os
import tempfile
import unittest

import dns
import mock
import requests_mock
from cryptography import x509 as crypto_x509
from cryptography.x509.oid import ExtensionOID, NameOID

from certcentral.acme_requests import (ACMEAccount, ACMEAccountFiles,
                                       ACMEChallengeNotValidatedError,
                                       ACMEChallengeType,
                                       ACMEChallengeValidation, ACMERequests,
                                       DNS01ACMEChallenge, HTTP01ACMEChallenge)
from certcentral.x509 import (CertificateSigningRequest, ECPrivateKey,
                              RSAPrivateKey)
from tests.test_pebble import BasePebbleIntegrationTest

DIRECTORY_URL = 'https://127.0.0.1:14000/dir'


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

    @mock.patch.object(dns.resolver.Resolver, 'query')
    def test_validate_dns(self, query_mock):
        challenge = DNS01ACMEChallenge(validation_domain_name='_acme-challenge.tests.wmflab.org',
                                       validation="fake_validation")

        rrset_mock = mock.MagicMock()
        rrset_mock.to_text.return_value = challenge.validation
        answer_mock = mock.MagicMock()
        answer_mock.rrset = [rrset_mock]
        query_mock.return_value = answer_mock
        result = challenge.validate()
        query_mock.assert_called_once_with(challenge.validation_domain_name, rdtype='TXT')
        self.assertEqual(result, ACMEChallengeValidation.VALID)

        rrset_mock.to_text.return_value = 'foo'
        query_mock.reset_mock()
        result = challenge.validate()
        query_mock.assert_called_once_with(challenge.validation_domain_name, rdtype='TXT')
        self.assertEqual(result, ACMEChallengeValidation.INVALID)

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
            result = challenge.validate()
            self.assertEqual(result, test_case['result'], test_case['name'])


class ACMEIntegrationTests(BasePebbleIntegrationTest):
    def test_account_persistence(self):
        with tempfile.TemporaryDirectory() as base_path:
            with mock.patch('certcentral.acme_requests.TLS_VERIFY', False):
                account = ACMEAccount.create('test-persistence@wikimedia.org',
                                             base_path=base_path,
                                             directory_url=DIRECTORY_URL)
            account.save()
            account_id = account.account_id

            for account_file in ACMEAccountFiles:
                file_path = os.path.join(base_path, account_id, account_file.value)
                self.assertTrue(os.path.isfile(file_path))

            with mock.patch('certcentral.acme_requests.TLS_VERIFY', False):
                load_account = ACMEAccount.load(account_id, base_path=base_path, directory_url=DIRECTORY_URL)
                self.assertIsInstance(load_account, ACMEAccount)
                self.assertIsInstance(ACMERequests(load_account), ACMERequests)

    def test_full_workflow_dns_challenge(self):
        """Expects pebble to be invoked with PEBBLE_VA_ALWAYS_VALID=1"""
        with mock.patch('certcentral.acme_requests.TLS_VERIFY', False):
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
        with mock.patch('certcentral.acme_requests.TLS_VERIFY', False):
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
        with mock.patch('certcentral.acme_requests.TLS_VERIFY', False):
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
