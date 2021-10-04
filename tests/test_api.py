import os
import re
import signal
import tempfile
import unittest
from unittest import mock

import yaml

from acme_chief.acme_chief import KEY_TYPES, ACMEChief
from acme_chief.api import create_app
from acme_chief.config import ACMEChiefConfig
from acme_chief.x509 import secure_opener

FILE_CONTENT = b'we do not care about the content'
FILE_MD5 = '781646e7499e9219059ef9a1e7453f9c'

CERT_VERSION = '32fb7e6f198e1b883d3691d5fc1b78d6'

METADATA_QUERY_PARAMS = {
    'checksum_type': 'md5',
    'links': 'manage',
    'source_permissions': 'ignore',
}

METADATAS_QUERY_PARAMS = {
    'recurse': 'true',
}

VALID_HEADERS = {'X_CLIENT_DN': 'CN=localhost'}

VALID_ROUTES = [
    '/certs/{certname}/{part}',
    '/certs/{certname}/{certversion}/{part}',
    '/puppet/v3/file_{api}/acmedata/{certname}/{certversion}/{part}',
    '/puppet/v3/file_{api}/acmedata/{certname}/{part}',
]

VALID_METADATA_ROUTE = '/puppet/v3/file_metadata/acmedata/{certname}'
VALID_METADATAS_ROUTE = '/puppet/v3/file_metadatas/acmedata/{certname}'


class ACMEChiefApiTest(unittest.TestCase):
    def setUp(self):
        self.config_path = tempfile.TemporaryDirectory()
        self.certificates_path = tempfile.TemporaryDirectory()
        self.config = ACMEChiefConfig(
            accounts=[],
            certificates={
                'test_certificate':
                {
                    'CN': 'acmechieftest.beta.wmflabs.org',
                    'SNI': ['acmechieftest.beta.wmflabs.org'],
                },
            },
            default_account=None,
            authorized_hosts={
                'test_certificate': {'localhost'}
            },
            authorized_regexes={
                'test_certificate': [re.compile('^host[1-3]$')]
            },
            challenges={
                'dns-01': {
                    'validation_dns_servers': ['127.0.0.1'],
                    'sync_dns_servers': ['127.0.0.1'],
                }
            },
            api={
                'clients_root_directory': '/etc/acmecerts',
            }
        )
        self._populate_files()
        self.app = create_app(config_dir=self.config_path.name,
                              certificates_dir=self.certificates_path.name,
                              acme_chief_config=self.config).test_client()

    def tearDown(self):
        self.config_path.cleanup()
        self.certificates_path.cleanup()

    @staticmethod
    def _get_valid_parts():
        for key_type in KEY_TYPES:
            # '{}.chained.crt.key.ocsp' is ommited here on purpose as it's a symlink instead of a regular file
            for file_name in ['{}.crt', '{}.crt.key', '{}.chain.crt', '{}.chained.crt', '{}.chained.crt.key',
                              '{}.alt.chain.crt', '{}.alt.chained.crt', '{}.alt.chained.crt.key',
                              '{}.key', '{}.ocsp']:
                yield file_name.format(key_type)

    @staticmethod
    def _get_invalid_parts():
        for key_type in KEY_TYPES:
            for file_name in ('{}.invalid.crt', '{}.invalid.key'):
                yield file_name.format(key_type)

    def _populate_files(self):
        for certname in self.config.certificates:
            cert_path = os.path.join(self.certificates_path.name, ACMEChief.certs_path, certname)
            os.makedirs(cert_path, mode=0o700)
            cert_version_path = os.path.join(cert_path, CERT_VERSION)
            os.mkdir(cert_version_path, mode=0o700)
            os.symlink(cert_version_path, os.path.join(cert_path, ACMEChief.live_symlink_name),
                       target_is_directory=True)

            for part in self._get_valid_parts():
                path = os.path.join(cert_version_path, part)
                with open(path, 'wb', opener=secure_opener) as cert_file:
                    cert_file.write(FILE_CONTENT)

            for key_type in KEY_TYPES:
                os.symlink('{}.ocsp'.format(key_type), os.path.join(cert_path, ACMEChief.live_symlink_name,
                                                                    '{}.chained.crt.key.ocsp'.format(key_type)))
                os.symlink('{}.ocsp'.format(key_type), os.path.join(cert_path, ACMEChief.live_symlink_name,
                                                                    '{}.alt.chained.crt.key.ocsp'.format(key_type)))

            for part in self._get_invalid_parts():
                path = os.path.join(cert_version_path, part)
                with open(path, 'wb', opener=secure_opener) as cert_file:
                    cert_file.write(FILE_CONTENT)


    def test_get_without_headers(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'part': 'ec-prime256v1.crt',
            'api': 'content',
            'certversion': 'unknown',
        }

        for route in VALID_ROUTES:
            fmt_route = route.format(**args)
            result = self.app.get(fmt_route)
            with self.subTest(route=fmt_route):
                self.assertEqual(result.status_code, 400)
                self.assertEqual(result.data, b'missing mandatory headers')

    def test_get_wrong_part(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'part': 'foobar',
            'api': 'content',
            'certversion': 'unknown',
        }

        for route in VALID_ROUTES:
            fmt_route = route.format(**args)
            result = self.app.get(fmt_route, headers=VALID_HEADERS)
            with self.subTest(route=fmt_route):
                self.assertEqual(result.status_code, 400)
                self.assertIn(b'part must be in', result.data)

    def test_get_unknown_certificate(self):
        args = {
            'certname': 'foo_certificate',
            'part': 'ec-prime256v1.crt',
            'api': 'content',
            'certversion': 'live',
        }

        for route in VALID_ROUTES:
            url = route.format(**args)
            result = self.app.get(url, headers=VALID_HEADERS)
            with self.subTest(url=url):
                self.assertEqual(result.status_code, 404)
                self.assertEqual(result.data, b'no such certname')

    @mock.patch('signal.signal')
    @mock.patch.object(ACMEChiefConfig, 'load')
    def test_sighup(self, acme_chief_config_load_mock, signal_mock):
        app = create_app(config_dir=self.config_path.name,
                         certificates_dir=self.certificates_path.name).test_client()
        (sig, f), _ = signal_mock.call_args
        self.assertEqual(sig, signal.SIGHUP)
        acme_chief_config_load_mock.reset_mock()
        f()  # simulate SIGHUP

        config_path = os.path.join(self.config_path.name, ACMEChief.config_path)
        confd_path = os.path.join(self.config_path.name, ACMEChief.confd_path)

        acme_chief_config_load_mock.assert_called_once_with(config_path, confd_path=confd_path)

    def test_access_denied(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'part': 'ec-prime256v1.crt',
            'api': 'content',
            'certversion': 'live',
        }

        for route in VALID_ROUTES:
            fmt_route = route.format(**args)
            result = self.app.get(fmt_route, headers={'X_CLIENT_DN': 'CN=foo.bar.test'})
            with self.subTest(route=fmt_route):
                self.assertEqual(result.status_code, 403)
                self.assertEqual(result.data, b'access denied')

    def test_get_contents(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'api': 'content',
            'certversion': CERT_VERSION,
        }

        for part in self._get_valid_parts():
            args['part'] = part
            for route in VALID_ROUTES:
                fmt_route = route.format(**args)
                result = self.app.get(fmt_route, headers=VALID_HEADERS)
                with self.subTest(route=fmt_route):
                    self.assertEqual(result.status_code, 200)
                    self.assertEqual(result.data, FILE_CONTENT)

    def test_get_metadata(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'api': 'metadata',
        }

        for part in self._get_valid_parts():
            args['part'] = part
            url = VALID_ROUTES[-1].format(**args)
            result = self.app.get(url, headers=VALID_HEADERS, query_string=METADATA_QUERY_PARAMS)
            with self.subTest(part=part, url=url):
                self.assertEqual(result.status_code, 200)
                metadata = yaml.safe_load(result.data)
                self.assertEqual(metadata['checksum']['type'], METADATA_QUERY_PARAMS['checksum_type'])
                self.assertEqual(metadata['links'], METADATA_QUERY_PARAMS['links'])
                self.assertEqual(metadata['checksum']['value'], '{md5}' + FILE_MD5)
                self.assertEqual(metadata['mode'], 0o640)
                self.assertEqual(metadata['type'], 'file')

    # FIXME: we should be returning PSON data according to
    # https://puppet.com/docs/puppet/4.8/http_api/http_file_metadata.html#supported-response-formats
    @unittest.expectedFailure
    def test_get_metadata_content_type(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'api': 'metadata',
        }
        for part in self._get_valid_parts():
            args['part'] = part
            url = VALID_ROUTES[-1].format(**args)
            result = self.app.get(url, headers=VALID_HEADERS, query_string=METADATA_QUERY_PARAMS)
            with self.subTest(part=part):
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.content_type, 'text/pson')


    def test_get_directory_metadatas(self):
        expected_metadata = {
            'directory': [],
            'file': [],
            'link': [],
        }
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'api': 'metadatas',
        }
        main_path = os.path.join(self.config.api['clients_root_directory'], args['certname'])
        expected_metadata['directory'].append((main_path, '.')) # /certname
        expected_metadata['directory'].append((main_path, CERT_VERSION)) # /certname/md5
        expected_metadata['link'].append((main_path, 'live')) # /certname/live
        expected_metadata['link'].append((main_path, 'new')) # /certname/new
        for part in self._get_valid_parts():
            expected_metadata['file'].append((main_path, os.path.join(CERT_VERSION, part))) # /certname/md5/part
        for key_type in KEY_TYPES:
            expected_metadata['link'].append((main_path, os.path.join(CERT_VERSION, '{}.chained.crt.key.ocsp'.format(key_type)))) # /certname/md5/{key_type_id}.chained.crt.key.ocsp
            expected_metadata['link'].append((main_path, os.path.join(CERT_VERSION, '{}.alt.chained.crt.key.ocsp'.format(key_type)))) # /certname/md5/{key_type_id}.alt.chained.crt.key.ocsp
        url = VALID_METADATAS_ROUTE.format(**args)
        result = self.app.get(url, headers=VALID_HEADERS, query_string=METADATAS_QUERY_PARAMS)
        self.assertEqual(result.status_code, 200)
        metadatas = yaml.safe_load(result.data)
        for metadata in metadatas:
            with self.subTest(metadata=metadata):
                self.assertIn(metadata['type'], expected_metadata)
                found = False
                for expected in expected_metadata[metadata['type']]:
                    if expected[0] == metadata['path'] and expected[1] == metadata['relative_path']:
                        found = True
                        break
                self.assertTrue(found, "Unexpected metadata entry in file_metadatas response")
                if metadata['type'] == 'directory':
                    self.assertEqual(metadata['checksum']['type'], 'ctime')
                elif metadata['type'] == 'link':
                    self.assertIn(main_path, metadata['destination'])

    def test_get_directory_metadata(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
        }

        url = VALID_METADATA_ROUTE.format(**args)
        result = self.app.get(url, headers=VALID_HEADERS, query_string=METADATA_QUERY_PARAMS)
        self.assertEqual(result.status_code, 200)
        metadata = yaml.safe_load(result.data)
        self.assertEqual(metadata['type'], 'directory')
        self.assertEqual(metadata['path'], os.path.join(self.config.api['clients_root_directory'], args['certname']))

    def test_get_unknown_certversion(self):
        args = {
            'certname': list(self.config.certificates.keys())[0],
            'api': 'metadata',
            'certversion': 'unkown',
        }
        for part in self._get_valid_parts():
            args['part'] = part
            for route in VALID_ROUTES[1:3]:
                url = route.format(**args)
                result = self.app.get(url, headers=VALID_HEADERS, query_string=METADATA_QUERY_PARAMS)
                with self.subTest(url=url):
                    self.assertEqual(result.status_code, 404)
