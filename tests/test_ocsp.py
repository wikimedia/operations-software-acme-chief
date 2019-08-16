import base64
import datetime
import os
import tempfile
import unittest

import requests_mock

from acme_chief.ocsp import OCSPRequest, OCSPResponse, OCSPResponseStatus, OCSPCertStatus
from acme_chief.x509 import Certificate


FULL_CHAIN = b'''
-----BEGIN CERTIFICATE-----
MIIIAzCCBuugAwIBAgISA3qQbJ1BNoGwyJ/TQsDpVsh9MA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTA3MjYwNzAwNDdaFw0x
OTEwMjQwNzAwNDdaMBoxGDAWBgNVBAMMDyoud2lraXBlZGlhLm9yZzCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANI2B0uyQBj1oJkJMM53DKv7rMkDZ1HB
2mabn4KEHcBs9sn0ctqjQrowynghlGQMusCwIbFw2CfRq8e105CDzwdtajIW3EGx
bHnF5vBnBwl8AkdhOquX8uNoCvLruYbVomW7hRja/++tmS9RDfIOyblBxRL+IMOL
nIbDoLZbdhGXcOdm/MzcrTtwuUBFJ9OfcHKm2T2qybdpzavHR5mSHzCXxN8n64B9
U2ny8BN7Sv/ZVSdyzHA3KUFVoqfgfh/H4jaZXcjjgY4Jko2JaQuels4MPKqCLpEB
OjjHdS9Um35OgNrcrLY6Tr6RD9sX0tB/umKNhlvnOT2sivwylpQsEUkCAwEAAaOC
BREwggUNMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUul5e90fZhlPnJ928mRy25bgp
17IwHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYIKwYBBQUHAQEE
YzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0c2VuY3J5cHQu
b3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0c2VuY3J5cHQu
b3JnLzCCAsUGA1UdEQSCArwwggK4ghEqLm0ubWVkaWF3aWtpLm9yZ4IRKi5tLndp
a2lib29rcy5vcmeCECoubS53aWtpZGF0YS5vcmeCESoubS53aWtpbWVkaWEub3Jn
ghAqLm0ud2lraW5ld3Mub3JnghEqLm0ud2lraXBlZGlhLm9yZ4IRKi5tLndpa2lx
dW90ZS5vcmeCEioubS53aWtpc291cmNlLm9yZ4ITKi5tLndpa2l2ZXJzaXR5Lm9y
Z4ISKi5tLndpa2l2b3lhZ2Uub3JnghIqLm0ud2lrdGlvbmFyeS5vcmeCDyoubWVk
aWF3aWtpLm9yZ4IWKi5wbGFuZXQud2lraW1lZGlhLm9yZ4IPKi53aWtpYm9va3Mu
b3Jngg4qLndpa2lkYXRhLm9yZ4IPKi53aWtpbWVkaWEub3JnghkqLndpa2ltZWRp
YWZvdW5kYXRpb24ub3Jngg4qLndpa2luZXdzLm9yZ4IPKi53aWtpcGVkaWEub3Jn
gg8qLndpa2lxdW90ZS5vcmeCECoud2lraXNvdXJjZS5vcmeCESoud2lraXZlcnNp
dHkub3JnghAqLndpa2l2b3lhZ2Uub3JnghAqLndpa3Rpb25hcnkub3JnghQqLndt
ZnVzZXJjb250ZW50Lm9yZ4INbWVkaWF3aWtpLm9yZ4IGdy53aWtpgg13aWtpYm9v
a3Mub3Jnggx3aWtpZGF0YS5vcmeCDXdpa2ltZWRpYS5vcmeCF3dpa2ltZWRpYWZv
dW5kYXRpb24ub3Jnggx3aWtpbmV3cy5vcmeCDXdpa2lwZWRpYS5vcmeCDXdpa2lx
dW90ZS5vcmeCDndpa2lzb3VyY2Uub3Jngg93aWtpdmVyc2l0eS5vcmeCDndpa2l2
b3lhZ2Uub3Jngg53aWt0aW9uYXJ5Lm9yZ4ISd21mdXNlcmNvbnRlbnQub3JnMEwG
A1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEW
Gmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBAYKKwYBBAHWeQIEAgSB9QSB
8gDwAHcA4mlLribo6UAJ6IYbtjuD1D7n/nSI+6SPKJMBnd3x2/4AAAFsLUvypAAA
BAMASDBGAiEA37IJ4yg0paPcp7OE9OCWrfksNy6H7WJwEbSLObXeivUCIQD4/UcD
TjBaTAseotlSaM2Zk7t2un10VD5PkLtrPEmGdwB1ACk8UZZUyDlluqpQ/FgH1Ldv
v1h6KXLcpMMM9OVFR/R4AAABbC1L8sgAAAQDAEYwRAIgLkjgSSvzpTUefV9NMaCx
NEmS48AcReJOVAnRqGwuhKkCIGUuTlYub2f4NIcgqAdqhQ92cnhaJQBxh+n35NqY
afKMMA0GCSqGSIb3DQEBCwUAA4IBAQBF7smBKE4JD6kzkvN9LaI33zTSYDUgKEfB
Cax/OWMRYk6x2nbV/k9JwQtaO/OK3gGzToYmldWW+Ot63iNm63S2sBthC/za4Sck
XRhzKgT/yoNlCfiXIhjNi0M81uo1DzBfTgChePFuvaTfgrpPrFehG5HxkBQcFgY9
0da1xXgiyh09NEsCNGm5nh3mnIh8ePUCW99ubVplnQdITmH20L4CxYdmPJlnDenE
wPK1krOyMddnCtpPpfRRbsvt3MQXrKziQ30CpifpnmsnzGQIaEfgt1s5aYSJAsl1
krKKkrmckCP221Oy6wGhhB0jTmexDvy/OyRPWj0sKc6uL2cfwTRs
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
'''

VALID_OCSP_RESPONSE_B64 = ('MIICCwoBAKCCAgQwggIABgkrBgEFBQcwAQEEggHxMIIB7TCB1qFMMEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQ'
                           'ncyBFbmNyeXB0MSMwIQYDVQQDExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMxgPMjAxOTA4MTMwODAxMDBaMHUwc'
                           'zBLMAkGBSsOAwIaBQAEFH7maudymrP8+KIgZGwWoS1gcQhdBBSoSmpjBH3duubRObemRWXv86jsoQISA3qQbJ1BNoG'
                           'wyJ/TQsDpVsh9gAAYDzIwMTkwODEzMDgwMDAwWqARGA8yMDE5MDgyMDA4MDAwMFowDQYJKoZIhvcNAQELBQADggEBA'
                           'Ct58MezSbDv6UGMCFH9X0wtBIjYBTmBk/H+uZwVJ4hpIxohEwBC9SGYISI1Ku5DQqP7h77HnR1m3GLhFJ91orK/B+4'
                           'cy6EH34VY2Zz7MDVy2+mqMQjbwn3eu5JPYxYJyWO3lypTdDnD690Q3/Zh0Ub8Yy3gzCee9DwHLh8CdQyiYZ99c8Kg/'
                           'MkemHooDMgL6TbCsVwL7p7DIOeVNHLFkM3/fYm4ebFBI2gatC6WxCxulT0AQOS6G2zNkEAAHUTBiwQlr+A/dUciQbA'
                           'sFw4OQIKP8EMAzNOys8C2t+szPSJlO9XXbvfqy076lopphNO1NZN/wOE4m4GAlqG9OBpZP7Q=')

class OCSPRequestTest(unittest.TestCase):
    def test_request_generation(self):
        cert = Certificate(FULL_CHAIN)
        ocsp_request = OCSPRequest(cert, cert.chain[1])
        with requests_mock.Mocker() as req_mock:
            req_mock.post(cert.ocsp_uri, content=base64.b64decode(VALID_OCSP_RESPONSE_B64))
            ocsp_response = ocsp_request.fetch_response()

        self.assertIsInstance(ocsp_response, OCSPResponse)
        self.assertIsInstance(ocsp_response.this_update, datetime.datetime)
        self.assertIsInstance(ocsp_response.next_update, datetime.datetime)
        self.assertIs(ocsp_response.response_status, OCSPResponseStatus.SUCCESSFUL)
        self.assertIs(ocsp_response.cert_status, OCSPCertStatus.GOOD)

        with tempfile.TemporaryDirectory() as tmp_dir:
            ocsp_response_path = os.path.join(tmp_dir, 'response.ocsp')
            ocsp_response.save(ocsp_response_path)
            with open(ocsp_response_path, 'rb') as ocsp_response_file:
                self.assertEqual(ocsp_response_file.read(), base64.b64decode(VALID_OCSP_RESPONSE_B64))

            self.assertIsInstance(ocsp_response.load(ocsp_response_path), OCSPResponse)
