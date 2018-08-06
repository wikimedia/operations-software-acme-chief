import datetime
import ipaddress
import os
import stat
import tempfile
import unittest
from unittest import mock

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from x509 import (DEFAULT_EC_CURVE, DEFAULT_RSA_KEY_SIZE, OPENER_MODE,
                  Certificate, CertificateSigningRequest, ECPrivateKey,
                  PrivateKey, PrivateKeyLoader, RSAPrivateKey,
                  SelfSignedCertificate, secure_opener)

RSA_TEST_KEY = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1tMp+1y+4lNmu7VEsp3VBqB7M6Ljmppy+6D/qCX25xhJO9CP
AjiPkgZgq2eAAUStDfAVIj/oQFJ1mQeaSfh31jBxRUr4Oz1Rzd8JWCHgyFk6kwUe
x639XNJEBV6EQm+XBTudCxzpDdxOIT7wWkx6T1vCeDg1PUBxIw8wJ1nDvfp+MFAj
xTuxgzhbaAbxKHqTtwppx952pgiM0AT7trKCTzMAvAIaH2z3MGtXReX2MLVPOHnL
Zjk+8al6oz0J2nJ9uWiF46bP74wjTTZNSss5EcleS3sUT9vRYckyfTbdvKzUiqj1
fPRjyTQWGnef7UNUsJRhjATevtiMR7IRFxh1RQIDAQABAoIBAQCx7ONwlThkK7+C
6HelmKO/gVuJQPhSLGnfj1Ev64G7lZnSOMK5jC8dOrsGPAsBAehzCs32OAgcfi94
N5vKeEiI1kZ6pcVDC16drIUIwcZzKbQh4LPFno2iO2SrLcVNYS8r3lwLwD4mhLkR
QBfCMmV7JPzEpYky2hTafNHdRbOhvDocSIi6a3dqT2ayQ5sokt89aBlO1Am8hSua
KqCWjYOSuhF6+CvR2Z7Iuxzhx4VDAGRl77AesqnFGwktVCLL4CJpZ06hLNKB7p44
MQYkFKc/7pFpGvr8YyXDde/GQFt4KpAobkZ6WAS7RZB2nGsc4e5a/yP5UInQnu7c
3Sc8RjsBAoGBAOy2YQjspYlAoYTTZTc5mn2jn477Srofdli3iPHZf2CiJd8Jmumv
kOGCmS+WhfvdqVdNFNSo8/CA2uelbq69lcFn1bQ4BegWKcW8aiKvF9V/ggtRi6Bc
fHKescmZBBZgP0PWWvv6rwU4e597NhaeZVX6ReIbWmOcoY3sQBHUa+qpAoGBAOhU
Op4FM6KESIFgtDnuqIKpjKEdVRn7IAf0Tz1cPx6oC1alfdVFYzGgREzm2vuruVeJ
M27hU+fkDN//Skyfz2zGpHoFTBITQdddVkRkQwMvxm5euuAWsmeFpip3O4/R0PH/
IZI896/lc7N/xBM0xZF1r7vOcTEQShZpRfv4nxM9AoGAO6wKMB6/6Caz0PEdfdt2
l5+M1JWClALkaZ7y1cz3cFvP4jbgp3JLup2akkWGxyRs0QYsbyOcQw+on2azzTcb
rmLHm6PX0Vbs9tz1gILVJkv7c3D+GtHVyWs59FEvl5hxul8qFoVuY4mGmICN9Qu/
DfqGbWZp1dyhWU6qJBSBk+kCgYADQ9PDDr2oBgXi05IU0lbJ50oTpY7hm5bapcNL
UHWOn7vxDshS6/O16dOr5P6k1Mf5A/OWFlKQirLnnvXTV9eZZr0+/b4Q7vZY6XXh
5irO66f1Ox2TMp51N/qa1CwhHEi8beJx5KtybF4Q4rXFs1MndSjwEbmjf+AaqoYS
QW8y3QKBgBKVu1yDdlmMajWc/HKW9lRvUBH8/G7QoIrX2KXSTv7PBMjADf2A3B8+
WqnkqazWkT8s4kyGh/upfiYWQm3WU+i+wPns+Z20QHax9b3sr+YJERMQ7BCh5B28
2BNTzNMrfERLM2YcDM5OKsi4YndgFgzHRYDrr9tDizdWUdCZaWDY
-----END RSA PRIVATE KEY-----
'''

EC_TEST_KEY = '''
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM9mZWQWbvGUuNsnFq1Y6M6e4Mm30e/j5W8IlmOyUSL5oAoGCCqGSM49
AwEHoUQDQgAEe635B78GCi84ub06L1Ow9OXKaIc63k4SRzFSGyJ1AXg6VxQBeeXt
r7o8yXlWBLv89THLlzqSKCC/bw1DpngsGg==
-----END EC PRIVATE KEY-----
'''

def get_self_signed_certificate(from_date, until_date):
    pk = RSAPrivateKey()
    pk.generate()
    return SelfSignedCertificate(
        private_key=pk,
        common_name="certcentral.test",
        sans=(
            '*.certcentral.test',
            ipaddress.IPv4Address('127.0.0.1'),
            ipaddress.IPv6Address('::1'),
        ),
        from_date=from_date,
        until_date=until_date,
    )

class PrivateKeyTest(unittest.TestCase):
    def test_key_generation(self):
        rsa_pk = RSAPrivateKey()
        rsa_pk.generate()
        ec_pk = ECPrivateKey()
        ec_pk.generate()

        self.assertIsInstance(rsa_pk.key, rsa.RSAPrivateKey)
        self.assertEqual(rsa_pk.key.key_size, DEFAULT_RSA_KEY_SIZE)
        self.assertIsInstance(ec_pk.key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(ec_pk.key.curve, DEFAULT_EC_CURVE)

    def test_key_generation_non_default_values(self):
        rsa_pk = RSAPrivateKey()
        rsa_pk.generate(size=4096)
        ec_pk = ECPrivateKey()
        ec_pk.generate(curve=ec.SECP521R1)

        self.assertIsInstance(rsa_pk.key, rsa.RSAPrivateKey)
        self.assertEqual(rsa_pk.key.key_size, 4096)

        self.assertIsInstance(ec_pk.key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(ec_pk.key.curve, ec.SECP521R1)


    def test_key_saving(self):
        pk = RSAPrivateKey()
        pk.generate()
        with tempfile.TemporaryDirectory() as tmpdir:
            pk.save(os.path.join(tmpdir, 'rsa.pem'))
            pk_stat = os.stat(os.path.join(tmpdir, 'rsa.pem'))

        # check private key file permissions
        self.assertEqual(stat.S_IMODE(pk_stat.st_mode), OPENER_MODE)

    def test_load_ec_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filename = os.path.join(tmpdir, 'ec.pem')
            with open(filename, "w", opener=secure_opener) as f:
                f.write(EC_TEST_KEY)
            key = PrivateKeyLoader.load(filename)

        self.assertIsInstance(key, ECPrivateKey)

    def test_load_rsa_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filename = os.path.join(tmpdir, 'rsa.pem')
            with open(filename, "w", opener=secure_opener) as f:
                f.write(RSA_TEST_KEY)
            key = PrivateKeyLoader.load(filename)

        self.assertIsInstance(key, RSAPrivateKey)

    def test_load_key_unsecure_permissions(self):
        def unsecure_opener(path, flags):
            return os.open(path, flags, 0o777)

        with tempfile.TemporaryDirectory() as tmpdir:
            filename = os.path.join(tmpdir, 'rsa.pem')
            with open(filename, "w", opener=unsecure_opener) as f:
                f.write(RSA_TEST_KEY)

            with self.assertRaises(Exception):
                PrivateKeyLoader.load(filename)


class CertificateSigningRequestTest(unittest.TestCase):
    def test_CSR_generation(self):
        pk = RSAPrivateKey()
        pk.generate()
        csr = CertificateSigningRequest(
            private_key=pk,
            common_name="certcentral.test",
            sans=(
                '*.certcentral.test',
                ipaddress.IPv4Address('127.0.0.1'),
                ipaddress.IPv6Address('::1'),
            ),
        )

        self.assertIsInstance(csr.request, crypto_x509.CertificateSigningRequest)
        self.assertIsInstance(csr.request.signature_hash_algorithm, hashes.SHA256)
        self.assertTrue(csr.request.is_signature_valid)
        cn = csr.request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        self.assertEqual(len(cn), 1)
        self.assertEqual(cn[0].value, "certcentral.test")
        sans = csr.request.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertEqual(sans.value.get_values_for_type(crypto_x509.DNSName), ['*.certcentral.test'])
        self.assertEqual(
            sans.value.get_values_for_type(crypto_x509.IPAddress),
            [ipaddress.IPv4Address('127.0.0.1'), ipaddress.IPv6Address('::1')]
        )
        self.assertTrue(csr.wildcard)

    def test_csr_without_sans(self):
        pk = RSAPrivateKey()
        pk.generate()
        csr = CertificateSigningRequest(
            private_key=pk,
            common_name="certcentral.test",
            sans=(),
        )
        self.assertFalse(csr.wildcard)


class SelfSignedCertificateTest(unittest.TestCase):
    def test_cert_generation(self):
        from_date = datetime.datetime.utcnow()
        until_date = from_date + datetime.timedelta(days=30)
        cert = get_self_signed_certificate(from_date, until_date)

        self.assertIsInstance(cert.certificate, crypto_x509.Certificate)
        self.assertIsInstance(cert.certificate.signature_hash_algorithm, hashes.SHA256)
        cn = cert.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        self.assertEqual(len(cn), 1)
        self.assertEqual(cn[0].value, "certcentral.test")
        sans = cert.certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertEqual(sans.value.get_values_for_type(crypto_x509.DNSName), ['*.certcentral.test'])
        self.assertEqual(
            sans.value.get_values_for_type(crypto_x509.IPAddress),
            [ipaddress.IPv4Address('127.0.0.1'), ipaddress.IPv6Address('::1')]
        )

        self.assertEqual(cert.certificate.not_valid_before, from_date.replace(microsecond=0))
        self.assertEqual(cert.certificate.not_valid_after, until_date.replace(microsecond=0))


class CertificateTest(unittest.TestCase):
    def test_certificate(self):
        from_date = datetime.datetime.utcnow()
        until_date = from_date + datetime.timedelta(days=90)
        initial_cert = get_self_signed_certificate(from_date, until_date)

        cert = Certificate(initial_cert.pem)
        self.assertIsInstance(cert.certificate, crypto_x509.Certificate)
        self.assertEqual(cert.chain, [cert])
        self.assertFalse(cert.needs_renew())
        mocked_now = until_date - datetime.timedelta(days=10)
        with mock.patch('x509.datetime') as mocked_datetime:
            mocked_datetime.utcnow = mock.Mock(return_value=mocked_now)
            self.assertTrue(cert.needs_renew())

