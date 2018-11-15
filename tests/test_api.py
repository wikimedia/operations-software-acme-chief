import mock
import os
import signal
import tempfile
import unittest

import yaml

from certcentral.certcentral import KEY_TYPES, CertCentral, CertCentralConfig
from certcentral.api import create_app
from certcentral.x509 import secure_opener

FILE_CONTENT = b'we do not care about the content'
FILE_MD5 = '781646e7499e9219059ef9a1e7453f9c'

METADATA_QUERY_PARAMS = {
    'checksum_type': 'md5',
    'links': 'manage',
    'source_permissions': 'ignore',
}

VALID_HEADERS = {'X_CLIENT_DN': 'CN=localhost'}

VALID_ROUTES = [
    '/certs/{certname}/{part}',
    '/puppet/v3/file_{api}/acmedata/{certname}/{part}',
]


class CertCentralApiTest(unittest.TestCase):
    def setUp(self):
        self.config_path = tempfile.TemporaryDirectory()
        self.certificates_path = tempfile.TemporaryDirectory()
        self.config = CertCentralConfig(
            accounts=[],
            certificates={
                'test_certificate':
                {
                    'CN': 'certcentraltest.beta.wmflabs.org',
                    'SNI': ['certcentraltest.beta.wmflabs.org'],
                },
            },
            default_account=None,
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
        self._populate_files()
        self.app = create_app(config_dir=self.config_path.name,
                              certificates_dir=self.certificates_path.name,
                              cert_central_config=self.config).test_client()

    def tearDown(self):
        self.config_path.cleanup()
        self.certificates_path.cleanup()

    @staticmethod
    def _get_valid_parts():
        for key_type in KEY_TYPES:
            for file_name in ['{}.crt', '{}.chain.crt', '{}.chained.crt', '{}.key']:
                yield file_name.format(key_type)

    def _populate_files(self):
        live_certs_path = os.path.join(self.certificates_path.name, CertCentral.live_certs_path)
        os.mkdir(live_certs_path, mode=0o700)

        for certname in self.config.certificates:
            for part in self._get_valid_parts():
                path = os.path.join(live_certs_path, '{}.{}'.format(certname, part))
                with open(path, 'wb', opener=secure_opener) as cert_file:
                    cert_file.write(FILE_CONTENT)

    def test_get_without_headers(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'part': 'ec-prime256v1.crt',
            'api': 'content',
        }

        for route in VALID_ROUTES:
            result = self.app.get(route.format(**args))
            self.assertEqual(result.status_code, 400)
            self.assertEqual(result.data, b'missing mandatory headers')

    def test_get_wrong_part(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'part': 'foobar',
            'api': 'content',
        }

        for route in VALID_ROUTES:
            result = self.app.get(route.format(**args), headers=VALID_HEADERS)
            self.assertEqual(result.status_code, 400)
            self.assertIn(b'part must be in', result.data)

    def test_get_unknown_certificate(self):
        args = {
            'certname': 'foo_certificate',
            'part': 'ec-prime256v1.crt',
            'api': 'content',
        }

        for route in VALID_ROUTES:
            result = self.app.get(route.format(**args), headers=VALID_HEADERS)
            self.assertEqual(result.status_code, 404)
            self.assertEqual(result.data, b'no such certname')

    @mock.patch('signal.signal')
    @mock.patch.object(CertCentralConfig, 'load')
    def test_sighup(self, cert_central_config_load_mock, signal_mock):
        app = create_app(config_dir=self.config_path.name,
                         certificates_dir=self.certificates_path.name).test_client()
        (sig, f), _ = signal_mock.call_args
        self.assertEqual(sig, signal.SIGHUP)
        cert_central_config_load_mock.reset_mock()
        f()  # simulate SIGHUP

        config_path = os.path.join(self.config_path.name, CertCentral.config_path)
        confd_path = os.path.join(self.config_path.name, CertCentral.confd_path)

        cert_central_config_load_mock.assert_called_once_with(config_path, confd_path=confd_path)

    def test_access_denied(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'part': 'ec-prime256v1.crt',
            'api': 'content',
        }

        for route in VALID_ROUTES:
            result = self.app.get(route.format(**args), headers={'X_CLIENT_DN': 'CN=foo.bar.test'})
            self.assertEqual(result.status_code, 403)
            self.assertEqual(result.data, b'access denied')

    def test_get_contents(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'api': 'content',
        }

        for part in self._get_valid_parts():
            args['part'] = part
            for route in VALID_ROUTES:
                result = self.app.get(route.format(**args), headers=VALID_HEADERS)
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.data, FILE_CONTENT)

    # FIXME: we should be returning PSON data according to
    # https://puppet.com/docs/puppet/4.8/http_api/http_file_metadata.html#supported-response-formats
    @unittest.expectedFailure
    def test_get_metadata(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'api': 'metadata',
        }

        for part in self._get_valid_parts():
            args['part'] = part
            url = VALID_ROUTES[-1].format(**args)
            result = self.app.get(url, headers=VALID_HEADERS, query_string=METADATA_QUERY_PARAMS)
            self.assertEqual(result.status_code, 200)
            metadata = yaml.safe_load(result.data)
            self.assertEqual(metadata['checksum']['type'], METADATA_QUERY_PARAMS['checksum_type'])
            self.assertEqual(metadata['links'], METADATA_QUERY_PARAMS['links'])
            self.assertEqual(metadata['checksum']['value'], '{md5}' + FILE_MD5)
            self.assertEqual(metadata['mode'], 0o600)
            self.assertEqual(metadata['type'], 'file')
            path = os.path.join(self.certificates_path.name,
                                CertCentral.live_certs_path,
                                '{}.{}'.format(args['certname'], args['part']))
            self.assertEqual(metadata['path'], path)

        # when fixed, move this assert into the previous loop
        self.assertEqual(result.content_type, 'text/pson')
