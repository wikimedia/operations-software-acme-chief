"""
Central certificates service API
Alex Monk <krenair@gmail.com>, May/June 2018
Valentin Gutierrez <vgutierrez@wikimedia.org> 2018
Wikimedia Foundation 2018
"""
import hashlib
import os
import signal
import stat

import flask
import yaml

from certcentral.certcentral import (PATHS, KEY_TYPES, CertCentral,
                                     CertCentralConfig)

REQUIRED_METADATA_PARAMETERS = {
    'checksum_type': 'md5',
    'links': 'manage',
    'source_permissions': 'ignore',
}


def abort(status_code, reason):
    """Raise an error with a customized response data"""
    flask.abort(flask.make_response(reason, status_code))


def get_file_metadata(file_path, file_contents):
    """Returns metadata as expected by puppet v3 API"""
    stat_ret = os.stat(file_path)
    return {
        'path': file_path,
        'relative_path': None,
        'links': 'manage',
        'owner': stat_ret.st_uid,
        'group': stat_ret.st_gid,
        'mode': stat.S_IMODE(stat_ret.st_mode),
        'type': 'file',
        'destination': None,
        'checksum': {
            'type': 'md5',
            'value': '{md5}' + hashlib.md5(file_contents).hexdigest()
        }
    }


def create_app(config_dir=PATHS['config'], certificates_dir=PATHS['certificates'], cert_central_config=None):
    """Creates the flask app with the embedded CertCentralConfig"""
    app = flask.Flask(__name__)

    live_certs_path = os.path.join(certificates_dir, CertCentral.live_certs_path)

    config_path = None
    confd_path = None
    state = {'config': cert_central_config}

    def sighup_handler():
        """
        When receiving SIGHUP signals, reload config.
        """
        app.logger.info("SIGHUP received")
        state['config'] = CertCentralConfig.load(config_path, confd_path=confd_path)

    if state['config'] is None:
        config_path = os.path.join(config_dir, CertCentral.config_path)
        confd_path = os.path.join(config_dir, CertCentral.confd_path)
        signal.signal(signal.SIGHUP, sighup_handler)
        sighup_handler()

    @app.route("/certs/<certname>/<part>")
    @app.route("/puppet/v3/file_<api>/acmedata/<certname>/<part>")
    def get_certs(certname=None, part=None, api=None):  # pylint: disable=unused-variable
        """
        This is the function that gets called whenever a server asks us for a certificate.
        It implements two different APIs - our own simple /certs/ as well as the Puppet fileserver
        API.
        For Puppet, it can also produce metadata about the file, including the path on our system,
        owner, group, mode, and an MD5 hash of the file contents.
        This function is responsible for checking the X_CLIENT_DN header given by Nginx corresponds
        to a hostname that has been authorized for access to the certificate it is requesting.
        """
        if api is not None:
            if api not in ['metadata', 'content']:
                abort(400, 'invalid puppet API call')
            if api == 'metadata':
                for parameter, value in REQUIRED_METADATA_PARAMETERS.items():
                    if flask.request.args.get(parameter) != value:
                        abort(501, 'not implemented')

        valid_parts = []
        for key_type_id in KEY_TYPES:
            valid_parts.append('{}.crt'.format(key_type_id))
            valid_parts.append('{}.chain.crt'.format(key_type_id))
            valid_parts.append('{}.chained.crt'.format(key_type_id))
            valid_parts.append('{}.key'.format(key_type_id))

        if part not in valid_parts:
            abort(400, 'part must be in {}'.format(valid_parts))

        client_dn = flask.request.headers.get('X_CLIENT_DN', '')
        if not client_dn.startswith('CN='):
            abort(400, 'missing mandatory headers')

        client_dn = client_dn[3:]

        app.logger.info(
            'Client %s identified as %s requested %s part %s',
            flask.request.remote_addr,
            client_dn,
            certname,
            part
        )

        if certname not in state['config'].certificates:
            abort(404, 'no such certname')

        if client_dn not in state['config'].authorized_hosts[certname]:
            abort(403, 'access denied')

        fname = '{}.{}'.format(certname, part)
        fpath = os.path.join(live_certs_path, fname)

        try:
            with open(fpath, 'rb') as requested_f:
                file_contents = requested_f.read()
        except OSError as ose:
            app.logger.error(ose)
            abort(503, 'unable to fulfill request')

        if api != 'metadata':
            return file_contents

        return flask.Response(yaml.dump(get_file_metadata(fpath, file_contents)), mimetype='text/yaml')

    return app


if __name__ == '__main__':
    create_app().run()
