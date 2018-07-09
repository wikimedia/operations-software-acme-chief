# Central certificates service
# Alex Monk <krenair@gmail.com>, May/June 2018

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
This module is the main source code behind Wikimedia's central certificates service.
A description of it can be found at https://phabricator.wikimedia.org/T194962
"""
import collections
import datetime
import hashlib
import os
import signal
import tempfile
import threading
import time
import traceback

from cryptography.hazmat.primitives.asymmetric import ec
import flask
import yaml

import acme_tiny

from x509 import (
    CertificateSigningRequest,
    ECPrivateKey,
    RSAPrivateKey,
    SelfSignedCertificate,
)

app = flask.Flask(__name__)  # pylint: disable=invalid-name

KEY_TYPES = {
    'ec-prime256v1': {
        'class': ECPrivateKey,
        'params': {
            'curve': ec.SECP256R1,
        }
    },
    'rsa-2048': {
        'class': RSAPrivateKey,
        'params': {
            'size': 2048,
        }
    }
}


class CertCentral():
    """
    This class just acts as a container for all the methods and state - config and authorised hosts
    data.
    """
    def __init__(self):
        self.config = None
        self.authorised_hosts = None
        signal.signal(signal.SIGHUP, self.sighup_handler)
        self.sighup_handler()

    def run(self):
        """
        Starts up the certificate management and HTTP listener threads.
        """
        acct_key = RSAPrivateKey()
        acct_key.generate()
        acct_key.save('/etc/certcentral/acct.key')   # TODO: Do we really need to generate this key on every start-up?
        self.create_initial_certs()
        threading.Thread(
            target=self.certificate_management,
            name="Issue and renew certificates"
        ).start()
        app.run()

    def sighup_handler(self, *_):
        """
        This is called whenever our process receives SIGHUP signals, it reloads our config and
        authorised hosts data.
        It is also called once at the beginning to perform initial setup.
        """
        with open('/etc/certcentral/config.yaml') as config_f:
            self.config = yaml.safe_load(config_f)
        temp_authorised_hosts = collections.defaultdict(list)
        for fname in os.listdir('/etc/certcentral/conf.d'):
            with open('/etc/certcentral/conf.d/{}'.format(fname)) as conf_f:
                conf_data = yaml.safe_load(conf_f)
                temp_authorised_hosts[conf_data['certname']].append(conf_data['hostname'])
        self.authorised_hosts = temp_authorised_hosts

    def create_initial_certs(self):
        """
        Creates initial certificates for everything that doesn't currently exist.
        This is so that web servers which depend on having a certificate to start can start and
        begin serving traffic so they can forward ACME challenges through to us - that will enable
        us to request a real certificate to replace our initial one.
        """
        for cert_id in self.config:
            for key_type_id, key_type_details in KEY_TYPES.items():
                public_key_filename = '{}.{}.public.pem'.format(cert_id, key_type_id)
                public_key_file = os.path.join('/etc/certcentral/live_certs', public_key_filename)
                private_key_filename = '{}.{}.private.pem'.format(cert_id, key_type_id)
                private_key_file = os.path.join('/etc/certcentral/live_certs', private_key_filename)
                if not os.path.exists(public_key_file) or not os.path.exists(private_key_file):
                    key = key_type_details['class']()
                    key.generate(**key_type_details['params'])
                    key.save(private_key_filename)

                    cert = SelfSignedCertificate(
                        private_key=key,
                        common_name="Snakeoil cert",
                        sans=(),
                        from_date=datetime.datetime.utcnow(),
                        until_date=datetime.datetime.utcnow() + datetime.timedelta(days=3),
                    )
                    cert.save(public_key_file)

    def certificate_management(self):  # pylint: disable=too-many-locals
        """
        This functions is started in a thread to perform regular tasks.
        It will begin attempting to request real certificates from the certificate authority.
        In future it will attempt to renew existing certificates.
        """
        # TODO: make this go through certs and renew where necessary
        have_certs = set()
        while True:
            for cert_id, cert_details in self.config.items():
                for key_type_id, key_type_details in KEY_TYPES.items():
                    if (cert_id, key_type_id) in have_certs:
                        continue
                    # some of this is borrowed from acme-setup too
                    temp_private_key = tempfile.NamedTemporaryFile()
                    private_key = key_type_details['class']()
                    private_key.generate(**key_type_details['params'])
                    private_key.save(temp_private_key.name)

                    csr_filename = '{}.{}.csr.pem'.format(cert_id, key_type_id)
                    csr_fullpath = os.path.join('/etc/certcentral/csrs', csr_filename)
                    csr = CertificateSigningRequest(
                        private_key=private_key,
                        common_name=cert_details['CN'],
                        sans=cert_details['SNI'],
                    )
                    csr.save(csr_fullpath)
                    # TODO: do ACME v2 DNS wildcard requests and write challenges to
                    # dns_challenges/{domain}
                    try:
                        # TODO: make this check for /.well-known/acme-challenge file on % of
                        # authorised hosts
                        signed_cert = acme_tiny.get_crt(
                            '/etc/certcentral/acct.key',
                            csr_fullpath,
                            '/etc/certcentral/http_challenges',
                            CA='https://acme-staging.api.letsencrypt.org'
                        )

                        public_cert_path = os.path.join(
                            '/etc/certcentral/live_certs',
                            '{}.{}.public.pem'.format(cert_id, key_type_id)
                        )
                        with open(public_cert_path, 'w+b') as public_cert_f:
                            public_cert_f.write(signed_cert.encode('utf-8'))

                        private_key_path = os.path.join(
                            '/etc/certcentral/live_certs',
                            '{}.{}.private.pem'.format(cert_id, key_type_id)
                        )
                        with open(private_key_path, 'w+b') as private_key_f:
                            private_key_f.write(temp_private_key.read())

                        have_certs.update([(cert_id, key_type_id)])
                    except Exception:  # pylint: disable=broad-except
                        traceback.print_exc()
                    temp_private_key.close()
                time.sleep(5)

    @app.route("/certs/<certname>/<part>")
    @app.route("/puppet/v3/file_<api>/acmedata/<certname>/<part>")
    def get_certs(self, certname=None, part=None, api=None):  # pylint: disable=too-many-return-statements
        """
        This is the function that gets called whenever a server asks us for a certificate.
        It implements two different APIs - our own simple /certs/ as well as the Puppet fileserver
        API.
        For Puppet, it can also produce metadata about the file, including the path on our system,
        owner, group, mode, and an MD5 hash of the file contents.
        This function is responsible for checking the X_CLIENT_DN header given by Nginx corresponds
        to a hostname that has been authorised for access to the certificate it is requesting.
        """
        if api is not None and api not in ['metadata', 'content']:
            return 'invalid puppet API call', 400

        valid_parts = []
        for key_type_id in KEY_TYPES:
            valid_parts.append('{}.public.pem'.format(key_type_id))
            valid_parts.append('{}.private.pem'.format(key_type_id))

        if part not in valid_parts:
            return 'part must be in {}'.format(valid_parts), 400

        client_dn = flask.request.headers['X_CLIENT_DN']
        if client_dn.startswith('CN='):
            client_dn = client_dn[3:]
        else:
            return 'your client DN looks funny', 400

        print('Client {} identified as {} requested {} part {}'.format(
            flask.request.remote_addr,
            client_dn,
            certname,
            part
        ))

        if certname not in self.config:
            return 'no such certname', 404

        if client_dn not in self.authorised_hosts[certname]:
            return 'gtfo', 403

        fpath = '/etc/certcentral/live_certs/{}.{}'.format(certname, part)
        with open(fpath, 'rb') as requested_f:
            file_contents = requested_f.read()

        assert flask.request.args.get('environment') == 'production'
        if api == 'metadata':
            assert flask.request.args.get('checksum_type') == 'md5'
            assert flask.request.args.get('links') == 'manage'
            assert flask.request.args.get('source_permissions') == 'ignore'
            stat_ret = os.stat(fpath)
            metadata = {
                'path': fpath,
                'relative_path': None,
                'links': 'manage',
                'owner': stat_ret.st_uid,
                'group': stat_ret.st_gid,
                'mode': stat_ret.st_mode & 0o777,  # ignore S_IFREG
                'type': 'file',
                'destination': None,
                'checksum': {
                    'type': 'md5',
                    'value': '{md5}' + hashlib.md5(file_contents).hexdigest()
                }
            }
            return flask.Response(yaml.dump(metadata), mimetype='text/yaml')
        else:
            return file_contents


if __name__ == '__main__':
    CertCentral().run()
