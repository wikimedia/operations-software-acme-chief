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

from acme_chief.x509 import (DEFAULT_EC_CURVE, DEFAULT_RSA_KEY_SIZE,
                             OPENER_MODE, Certificate, CertificateSaveMode,
                             CertificateSigningRequest, ECPrivateKey,
                             PrivateKey, PrivateKeyLoader, RSAPrivateKey,
                             SelfSignedCertificate, X509Error, secure_opener)

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

FULL_CHAIN = b'''
-----BEGIN CERTIFICATE-----
MIIIfDCCB2SgAwIBAgIQCDCUYtH+pgrgur/174vFRTANBgkqhkiG9w0BAQsFADBw
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMS8wLQYDVQQDEyZEaWdpQ2VydCBTSEEyIEhpZ2ggQXNz
dXJhbmNlIFNlcnZlciBDQTAeFw0xNzEyMjEwMDAwMDBaFw0xOTAxMjQxMjAwMDBa
MHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMSMwIQYDVQQKExpXaWtpbWVkaWEgRm91bmRhdGlvbiwgSW5j
LjEYMBYGA1UEAwwPKi53aWtpcGVkaWEub3JnMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE/cBrHlZz40YZjqpIs3sTvwssebIFnhxwfJe3cm2ki4Ij0jLeUCMcPbpt
K3F49QKLsIQN4TZVOuTlBK1uem6H36OCBdIwggXOMB8GA1UdIwQYMBaAFFFo/5Cv
Agd1PMzZZWRiohK4WXI7MB0GA1UdDgQWBBRurRGx7mcc61Td8ipmVMG+0DsoOTCC
AvgGA1UdEQSCAu8wggLrgg8qLndpa2lwZWRpYS5vcmeCDXdpa2lwZWRpYS5vcmeC
ESoubS53aWtpcGVkaWEub3JnghQqLnplcm8ud2lraXBlZGlhLm9yZ4INd2lraW1l
ZGlhLm9yZ4IPKi53aWtpbWVkaWEub3JnghEqLm0ud2lraW1lZGlhLm9yZ4IWKi5w
bGFuZXQud2lraW1lZGlhLm9yZ4INbWVkaWF3aWtpLm9yZ4IPKi5tZWRpYXdpa2ku
b3JnghEqLm0ubWVkaWF3aWtpLm9yZ4INd2lraWJvb2tzLm9yZ4IPKi53aWtpYm9v
a3Mub3JnghEqLm0ud2lraWJvb2tzLm9yZ4IMd2lraWRhdGEub3Jngg4qLndpa2lk
YXRhLm9yZ4IQKi5tLndpa2lkYXRhLm9yZ4IMd2lraW5ld3Mub3Jngg4qLndpa2lu
ZXdzLm9yZ4IQKi5tLndpa2luZXdzLm9yZ4INd2lraXF1b3RlLm9yZ4IPKi53aWtp
cXVvdGUub3JnghEqLm0ud2lraXF1b3RlLm9yZ4IOd2lraXNvdXJjZS5vcmeCECou
d2lraXNvdXJjZS5vcmeCEioubS53aWtpc291cmNlLm9yZ4IPd2lraXZlcnNpdHku
b3JnghEqLndpa2l2ZXJzaXR5Lm9yZ4ITKi5tLndpa2l2ZXJzaXR5Lm9yZ4IOd2lr
aXZveWFnZS5vcmeCECoud2lraXZveWFnZS5vcmeCEioubS53aWtpdm95YWdlLm9y
Z4IOd2lrdGlvbmFyeS5vcmeCECoud2lrdGlvbmFyeS5vcmeCEioubS53aWt0aW9u
YXJ5Lm9yZ4IXd2lraW1lZGlhZm91bmRhdGlvbi5vcmeCGSoud2lraW1lZGlhZm91
bmRhdGlvbi5vcmeCGyoubS53aWtpbWVkaWFmb3VuZGF0aW9uLm9yZ4ISd21mdXNl
cmNvbnRlbnQub3JnghQqLndtZnVzZXJjb250ZW50Lm9yZ4IGdy53aWtpMA4GA1Ud
DwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdQYDVR0f
BG4wbDA0oDKgMIYuaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItaGEtc2Vy
dmVyLWc2LmNybDA0oDKgMIYuaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NoYTIt
aGEtc2VydmVyLWc2LmNybDBMBgNVHSAERTBDMDcGCWCGSAGG/WwBATAqMCgGCCsG
AQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAECAjCB
gwYIKwYBBQUHAQEEdzB1MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
dC5jb20wTQYIKwYBBQUHMAKGQWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
aWdpQ2VydFNIQTJIaWdoQXNzdXJhbmNlU2VydmVyQ0EuY3J0MAwGA1UdEwEB/wQC
MAAwggEGBgorBgEEAdZ5AgQCBIH3BIH0APIAdwC72d+8H4pxtZOUI5eqkntHOFeV
CqtS6BqQlmQ2jh7RhQAAAWB6Rb/PAAAEAwBIMEYCIQCYBInG8WHe18O9vaEPnHxH
LYRqOcc7wiG6SCybdpzCTQIhAIgDyjxagryxHN2Y4vraBjPd/OsIi5KWNmf7uXph
IQ6gAHcAh3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16ggw8AAAFgekXAKAAA
BAMASDBGAiEAxInIUUoY+UKfTiQfcQt0Bq+RV/oKF6Qvivhful45z3wCIQCUgFZz
FpBXRl1puoXQ8S379GmZm6h8pDEPnrFymBix1DANBgkqhkiG9w0BAQsFAAOCAQEA
Cn7jA1gpa8XvPlZoaYjHBLdcBEAJDKS4at1GHvaXrEGN6wc4tURSlC8J02SV9t9I
QmQ/yVwk4OYzGBqWAqCDNkvCEblead7ENhWEUdGqVzlJT2Pjp2KUtHHLTITmEY2l
GGY7amjEJcyJpxaEbZW8OBoiXajz7DlIl+Inh0mYtAtQl3QK6dnBPRyKBItRvfSy
AjL+a6v0Ad4OHuTjbYpXKRHgKu9ewVxjP2NE668rLy2bCXCdw1H3KX7NtsPHlLW4
QOtJM8xSDR4B5/V51y6yxilSHgv9rNouLc+7JChE+5aS74OlqwyMIqHg7Tuhbxt9
w6L7TYVnAT0Usyda5d06Ew==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEsTCCA5mgAwIBAgIQBOHnpNxc8vNtwCtCuF0VnzANBgkqhkiG9w0BAQsFADBs
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
ZSBFViBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcDEL
MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
LmRpZ2ljZXJ0LmNvbTEvMC0GA1UEAxMmRGlnaUNlcnQgU0hBMiBIaWdoIEFzc3Vy
YW5jZSBTZXJ2ZXIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2
4C/CJAbIbQRf1+8KZAayfSImZRauQkCbztyfn3YHPsMwVYcZuU+UDlqUH1VWtMIC
Kq/QmO4LQNfE0DtyyBSe75CxEamu0si4QzrZCwvV1ZX1QK/IHe1NnF9Xt4ZQaJn1
itrSxwUfqJfJ3KSxgoQtxq2lnMcZgqaFD15EWCo3j/018QsIJzJa9buLnqS9UdAn
4t07QjOjBSjEuyjMmqwrIw14xnvmXnG3Sj4I+4G3FhahnSMSTeXXkgisdaScus0X
sh5ENWV/UyU50RwKmmMbGZJ0aAo3wsJSSMs5WqK24V3B3aAguCGikyZvFEohQcft
bZvySC/zA/WiaJJTL17jAgMBAAGjggFJMIIBRTASBgNVHRMBAf8ECDAGAQH/AgEA
MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
NAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
dC5jb20wSwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29t
L0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNybDA9BgNVHSAENjA0MDIG
BFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQ
UzAdBgNVHQ4EFgQUUWj/kK8CB3U8zNllZGKiErhZcjswHwYDVR0jBBgwFoAUsT7D
aQP4v0cB1JgmGggC72NkK8MwDQYJKoZIhvcNAQELBQADggEBABiKlYkD5m3fXPwd
aOpKj4PWUS+Na0QWnqxj9dJubISZi6qBcYRb7TROsLd5kinMLYBq8I4g4Xmk/gNH
E+r1hspZcX30BJZr01lYPf7TMSVcGDiEo+afgv2MW5gxTs14nhr9hctJqvIni5ly
/D6q1UEL2tU2ob8cbkdJf17ZSHwD2f2LSaCYJkJA69aSEaRkCldUxPUd1gJea6zu
xICaEnL6VpPX/78whQYwvwt/Tv9XBZ0k7YXDK/umdaisLRbvfXknsuvCnQsH6qqF
0wGjIChBWUMo0oHjqvbsezt3tkBigAVBRQHvFwY+3sAzm2fTYS5yh+Rp/BIAV0Ae
cPUeybQ=
-----END CERTIFICATE-----
'''
FIRST_CERT_SERIAL_NUMBER = 0x8309462d1fea60ae0babff5ef8bc545
SECOND_CERT_SERIAL_NUMBER = 0x4e1e7a4dc5cf2f36dc02b42b85d159f

def get_self_signed_certificate(from_date, until_date):
    pk = RSAPrivateKey()
    pk.generate()
    return SelfSignedCertificate(
        private_key=pk,
        common_name="acmechief.test",
        sans=(
            '*.acmechief.test',
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

            with self.assertRaises(X509Error):
                PrivateKeyLoader.load(filename)


class CertificateSigningRequestTest(unittest.TestCase):
    def test_CSR_generation(self):
        pk = RSAPrivateKey()
        pk.generate()
        csr_sans = (
                '*.acmechief.test',
                ipaddress.IPv4Address('127.0.0.1'),
                ipaddress.IPv6Address('::1'),
        )
        csr = CertificateSigningRequest(
            private_key=pk,
            common_name="acmechief.test",
            sans=csr_sans,
        )

        self.assertIsInstance(csr.request, crypto_x509.CertificateSigningRequest)
        self.assertIsInstance(csr.request.signature_hash_algorithm, hashes.SHA256)
        self.assertTrue(csr.request.is_signature_valid)
        cn = csr.request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        self.assertEqual(len(cn), 1)
        self.assertEqual(cn[0].value, "acmechief.test")
        sans = csr.request.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertEqual(sans.value.get_values_for_type(crypto_x509.DNSName), ['*.acmechief.test'])
        self.assertEqual(
            sans.value.get_values_for_type(crypto_x509.IPAddress),
            [ipaddress.IPv4Address('127.0.0.1'), ipaddress.IPv6Address('::1')]
        )
        self.assertEqual(csr.csr_id, CertificateSigningRequest.generate_csr_id(pk.public_pem,
                                                                               'acmechief.test',
                                                                               csr_sans))
        self.assertTrue(csr.wildcard)

    def test_csr_without_sans(self):
        pk = RSAPrivateKey()
        pk.generate()
        csr = CertificateSigningRequest(
            private_key=pk,
            common_name="acmechief.test",
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
        self.assertEqual(cn[0].value, "acmechief.test")
        sans = cert.certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertEqual(sans.value.get_values_for_type(crypto_x509.DNSName), ['*.acmechief.test'])
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
        private_key = initial_cert.private_key

        cert = Certificate(initial_cert.pem)
        self.assertIsInstance(cert.certificate, crypto_x509.Certificate)
        self.assertEqual(cert.chain, [cert])
        self.assertFalse(cert.needs_renew())
        self.assertTrue(cert.self_signed)
        self.assertIsNone(cert.ocsp_uri)
        mocked_now = until_date - datetime.timedelta(days=10)
        with mock.patch('acme_chief.x509.datetime') as mocked_datetime:
            mocked_datetime.utcnow = mock.Mock(return_value=mocked_now)
            self.assertTrue(cert.needs_renew())

        with tempfile.TemporaryDirectory() as temp_dir:
            full_chain_cert = Certificate(FULL_CHAIN)
            # sanity check
            self.assertEqual(len(full_chain_cert.chain), 2)
            self.assertEqual(full_chain_cert.chain[0].certificate.serial_number, FIRST_CERT_SERIAL_NUMBER)
            self.assertEqual(full_chain_cert.chain[1].certificate.serial_number, SECOND_CERT_SERIAL_NUMBER)

            cert_only_path = os.path.join(temp_dir, 'cert.crt')
            cert_key_path = os.path.join(temp_dir, 'cert.crt.key')
            chain_only_path = os.path.join(temp_dir, 'chain.crt')
            full_chain_path = os.path.join(temp_dir, 'chained.crt')
            full_chain_cert.save(cert_only_path, mode=CertificateSaveMode.CERT_ONLY)
            full_chain_cert.save(cert_key_path, mode=CertificateSaveMode.CERT_ONLY, embedded_key=private_key)
            full_chain_cert.save(chain_only_path, mode=CertificateSaveMode.CHAIN_ONLY)
            full_chain_cert.save(full_chain_path, mode=CertificateSaveMode.FULL_CHAIN)

            cert_only = Certificate.load(cert_only_path)
            self.assertEqual(len(cert_only.chain), 1)
            self.assertEqual(cert_only.certificate.serial_number, FIRST_CERT_SERIAL_NUMBER)
            self.assertEqual(cert_only.ocsp_uri, 'http://ocsp.digicert.com')
            with self.assertRaises((ValueError, X509Error)):
                PrivateKeyLoader.load(cert_only_path)

            cert_key = Certificate.load(cert_key_path)
            self.assertEqual(len(cert_key.chain), 1)
            self.assertEqual(cert_key.certificate.serial_number, FIRST_CERT_SERIAL_NUMBER)
            self.assertEqual(cert_key.ocsp_uri, 'http://ocsp.digicert.com')
            embedded_key = PrivateKeyLoader.load(cert_key_path)
            self.assertIsInstance(embedded_key, RSAPrivateKey)

            chain_only = Certificate.load(chain_only_path)
            self.assertEqual(len(chain_only.chain), 1)
            self.assertEqual(chain_only.certificate.serial_number, SECOND_CERT_SERIAL_NUMBER)
            with self.assertRaises((ValueError, X509Error)):
                PrivateKeyLoader.load(chain_only_path)

            full_chain = Certificate.load(full_chain_path)
            self.assertEqual(len(full_chain.chain), 2)
            self.assertEqual(full_chain.chain[0].certificate.serial_number, FIRST_CERT_SERIAL_NUMBER)
            self.assertEqual(full_chain.chain[1].certificate.serial_number, SECOND_CERT_SERIAL_NUMBER)
            with self.assertRaises((ValueError, X509Error)):
                PrivateKeyLoader.load(full_chain_path)

