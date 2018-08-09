"""
Central certificates service API
Alex Monk <krenair@gmail.com>, May/June 2018
Valentin Gutierrez <vgutierrez@wikimedia.org> 2018
Wikimedia Foundation 2018
"""
import hashlib
import os

import flask
import yaml

from certcentral import BASEPATH, KEY_TYPES, CertCentral, CertCentralConfig


def create_app(base_path=BASEPATH, cert_central_config=None):
    """Creates the flask app with the embedded CertCentralConfig"""
    config_path = os.path.join(base_path, CertCentral.config_path)
    confd_path = os.path.join(base_path, CertCentral.confd_path)
    live_certs_path = os.path.join(base_path, CertCentral.live_certs_path)

    if cert_central_config is None:
        CertCentralConfig.load(config_path, confd_path=confd_path)

    app = flask.Flask(__name__)

    @app.route("/certs/<certname>/<part>")
    @app.route("/puppet/v3/file_<api>/acmedata/<certname>/<part>")
    def get_certs(certname=None, part=None, api=None):  # pylint: disable=too-many-return-statements,unused-variable
        """
        This is the function that gets called whenever a server asks us for a certificate.
        It implements two different APIs - our own simple /certs/ as well as the Puppet fileserver
        API.
        For Puppet, it can also produce metadata about the file, including the path on our system,
        owner, group, mode, and an MD5 hash of the file contents.
        This function is responsible for checking the X_CLIENT_DN header given by Nginx corresponds
        to a hostname that has been authorized for access to the certificate it is requesting.
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

        if certname not in cert_central_config.certificates:
            return 'no such certname', 404

        if client_dn not in cert_central_config.authorized_hosts[certname]:
            return 'gtfo', 403

        fname = '{}.{}'.format(certname, part)
        fpath = os.path.join(live_certs_path, fname)
        with open(fpath, 'rb') as requested_f:
            file_contents = requested_f.read()

        assert flask.request.args.get('environment') in ['production', None]
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

    return app


if __name__ == '__main__':
    create_app().run()
