import hashlib
import os
import tempfile
import unittest

import mock
from cryptography import x509 as crypto_x509
from cryptography.x509.oid import ExtensionOID, NameOID

from acme_requests import (ACMEAccount, ACMEAccountFiles, ACMEChallengeType,
                           ACMERequests, HTTP01ACMEChallenge)
from test_pebble import BasePebbleIntegrationTest
from x509 import (CertificateSigningRequest, ECPrivateKey, RSAPrivateKey,
                  SelfSignedCertificate)

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
    def test_save_http(self):
        challenge = HTTP01ACMEChallenge(hostname='tests.wmflabs.org',
                                        path='/.well-known/acme-challenge/BMHfMfFy0DtWYRwjxMFFSkmYZS5azT58-4YDrWfW_l4',
                                        validation='BMHfMfFy0DtWYRwjxMFFSkmYZS5azT58-4YDrWfW_l4.xnhzweFE-KO1EIuyHhY7iFw7ROdIN_uPCXG2tYK-Sv8')
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge_path = os.path.join(temp_dir, challenge.file_name)
            challenge.save(os.path.join(challenge_path))

            with open(challenge_path, 'r') as challenge_file:
                validation = challenge_file.read()
                self.assertEqual(validation, challenge.validation)


class ACMEIntegrationTests(BasePebbleIntegrationTest):
    def test_account_persistence(self):
        with tempfile.TemporaryDirectory() as base_path:
            with mock.patch('acme_requests.TLS_VERIFY', False):
                account = ACMEAccount.create('test-persistence@wikimedia.org',
                                             base_path=base_path,
                                             directory_url=DIRECTORY_URL)
            account.save()
            account_id = account.account_id

            for account_file in ACMEAccountFiles:
                file_path = os.path.join(base_path, account_id, account_file.value)
                self.assertTrue(os.path.isfile(file_path))

            with mock.patch('acme_requests.TLS_VERIFY', False):
                load_account = ACMEAccount.load(account_id, base_path=base_path, directory_url=DIRECTORY_URL)
                self.assertIsInstance(load_account, ACMEAccount)
                self.assertIsInstance(ACMERequests(load_account), ACMERequests)

    def test_full_workflow_dns_challenge(self):
        """Expects pebble to be invoked with PEBBLE_VA_ALWAYS_VALID=1"""
        with mock.patch('acme_requests.TLS_VERIFY', False):
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
        certificate = session.get_certificate(csr.csr_id)
        # pebble adds a random delay on validations, so we need to pull until we
        # get the certificate
        while certificate is None:
            self.assertTrue(session.orders)
            certificate = session.get_certificate(csr.csr_id)
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
        with mock.patch('acme_requests.TLS_VERIFY', False):
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
        certificate = session.get_certificate(csr.csr_id)
        while certificate is None:
            self.assertTrue(session.orders)
            certificate = session.get_certificate(csr.csr_id)
        self.assertFalse(session.orders)
        self.assertFalse(certificate.needs_renew())
        self.assertFalse(certificate.self_signed)
        self.assertEqual(len(certificate.chain), 2)
        sans = certificate.certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertEqual(sans.value.get_values_for_type(crypto_x509.DNSName), ['tests.wmflabs.org'])

    def test_full_workflow_ec_certificate(self):
        """Expects pebble to be invoked with PEBBLE_VA_ALWAYS_VALID=1"""
        with mock.patch('acme_requests.TLS_VERIFY', False):
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
        certificate = session.get_certificate(csr.csr_id)
        while certificate is None:
            self.assertTrue(session.orders)
            certificate = session.get_certificate(csr.csr_id)
        self.assertFalse(session.orders)
        self.assertFalse(certificate.needs_renew())
        self.assertFalse(certificate.self_signed)
        self.assertEqual(len(certificate.chain), 2)
        sans = certificate.certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertEqual(sans.value.get_values_for_type(crypto_x509.DNSName),
                         ['tests.wmflabs.org', '*.tests.wmflabs.org'])
