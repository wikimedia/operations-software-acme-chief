"""
ACMEChief service API
Alex Monk <krenair@gmail.com>, May/June 2018
Valentin Gutierrez <vgutierrez@wikimedia.org> 2018
Wikimedia Foundation 2018
"""
import hashlib
import os
import pathlib
import signal
import stat
from datetime import datetime

import flask
import yaml

from acme_chief.acme_chief import (PATHS, KEY_TYPES, ACMEChief)
from acme_chief.config import ACMEChiefConfig

REQUIRED_PARAMETERS = {
    'metadata': {
        'checksum_type': 'md5',
        'links': 'manage',
        'source_permissions': 'ignore',
    },
    'metadatas': {
        'recurse': 'true',
    }
}

PARTS = (
    '.crt',
    '.crt.key',
    '.chain.crt',
    '.chained.crt',
    '.chained.crt.key',
    '.alt.chain.crt',
    '.alt.chained.crt',
    '.alt.chained.crt.key',
    '.key',
    '.ocsp',
)


def abort(status_code, reason):
    """Raise an error with a customized response data"""
    flask.abort(flask.make_response(reason, status_code))


def get_file_metadata(file_path, file_contents, clients_path):
    """Returns metadata as expected by puppet v3 API."""
    path = pathlib.Path(file_path)
    destination = None
    file_path_split = file_path.split(os.sep)
    # symlink check must be the first one, cause for a symlink to a directory, both is_symlink() and is_dir() ret True
    if path.is_symlink():
        file_type = 'link'
        destination = str(path.resolve())
        puppet_path = os.path.join(clients_path, file_path_split[-2], file_path_split[-1])
    elif path.is_dir():
        file_type = 'directory'
        puppet_path = os.path.join(clients_path, file_path_split[-1])
    elif path.is_file():
        file_type = 'file'
        puppet_path = os.path.join(clients_path, file_path_split[-2], file_path_split[-1])

    stat_ret = path.stat()

    if file_contents is None:
        ctime_dt = datetime.utcfromtimestamp(stat_ret.st_ctime).astimezone()
        checksum_type = 'ctime'
        checksum_value = '{ctime}' + ctime_dt.strftime('%Y-%m-%d %H:%M:%S %z')
    else:
        checksum_type = 'md5'
        checksum_value = '{md5}' + hashlib.md5(file_contents).hexdigest()

    return {
        'path': puppet_path,
        'relative_path': None,
        'links': 'manage',
        'owner': stat_ret.st_uid,
        'group': stat_ret.st_gid,
        'mode': stat.S_IMODE(stat_ret.st_mode),
        'type': file_type,
        'destination': destination,
        'checksum': {
            'type': checksum_type,
            'value': checksum_value,
        }
    }


def get_directory_metadata(certname, directory_path, clients_path, valid_parts):
    """Generates the metadata for a whole certname directory and fixes paths to make Puppet clients happy"""
    ret = []
    ret.append(get_file_metadata(directory_path, None, clients_path))
    ret[0]['relative_path'] = '.'

    for root, dirs, files in os.walk(directory_path, followlinks=False):
        for dirname in dirs:
            dir_metadata = get_file_metadata(os.path.join(root, dirname), None, clients_path)
            dir_metadata['path'] = os.path.join(clients_path, certname)
            dir_metadata['relative_path'] = dirname
            if dir_metadata['destination'] is not None:
                dir_metadata['destination'] = os.path.join(clients_path, certname,
                                                           dir_metadata['destination'].rsplit(os.sep, maxsplit=1)[1])
            ret.append(dir_metadata)
        for file_name in files:
            if file_name not in valid_parts:
                continue
            file_path = os.path.join(root, file_name)
            try:
                with open(file_path, 'rb') as explored_f:
                    file_contents = explored_f.read()
            except OSError:
                continue

            file_metadata = get_file_metadata(file_path, file_contents, clients_path)
            file_metadata['relative_path'] = os.path.join(file_metadata['path'].split(os.sep)[-2], file_name)
            file_metadata['path'] = os.path.join(clients_path, certname)
            ret.append(file_metadata)

    return ret


def create_app(config_dir=PATHS['config'], certificates_dir=PATHS['certificates'], acme_chief_config=None):  # noqa: E501 pylint: disable=too-many-statements
    """Creates the flask app with the embedded ACMEChiefConfig"""
    app = flask.Flask(__name__)

    config_path = None
    confd_path = None
    state = {'config': acme_chief_config}

    valid_parts = []
    for key_type_id in KEY_TYPES:
        for part in PARTS:
            valid_parts.append(key_type_id + part)

    def sighup_handler():
        """
        When receiving SIGHUP signals, reload config.
        """
        app.logger.info("SIGHUP received")
        state['config'] = ACMEChiefConfig.load(config_path, confd_path=confd_path)

    if state['config'] is None:
        config_path = os.path.join(config_dir, ACMEChief.config_path)
        confd_path = os.path.join(config_dir, ACMEChief.confd_path)
        signal.signal(signal.SIGHUP, sighup_handler)
        sighup_handler()

    @app.route("/certs/<certname>/<part>")
    @app.route("/certs/<certname>/<certversion>/<part>")
    @app.route("/puppet/v3/file_<api>/acmedata/<certname>")
    @app.route("/puppet/v3/file_<api>/acmedata/<certname>/<certversion>/<part>")
    @app.route("/puppet/v3/file_<api>/acmedata/<certname>/<part>")
    def get_certs(certname=None, part=None, api=None, certversion=None):  # noqa: E501 pylint: disable=unused-variable,too-many-branches
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
            if api not in ('metadata', 'metadatas', 'content'):
                abort(400, 'invalid puppet API call')
            if api in ('metadata', 'metadatas'):
                for parameter, value in REQUIRED_PARAMETERS[api].items():
                    if flask.request.args.get(parameter) != value:
                        abort(501, 'not implemented')

        if part is not None and part not in valid_parts:
            abort(400, 'part must be in {}'.format(valid_parts))

        client_dn = flask.request.headers.get('X_CLIENT_DN', '')
        if not client_dn.startswith('CN='):
            abort(400, 'missing mandatory headers')

        client_dn = client_dn[3:]

        if certname not in state['config'].certificates:
            abort(404, 'no such certname')

        certname_path = os.path.join(certificates_dir, ACMEChief.certs_path, certname)

        if certversion is None:
            if part is not None:
                certversion = ACMEChief.live_symlink_name
        else:
            if not os.path.exists(os.path.join(certname_path, certversion)):
                abort(404, 'unknown certversion')

        app.logger.info(
            'Client %s identified as %s requested %s version %s part %s',
            flask.request.remote_addr,
            client_dn,
            certname,
            certversion,
            part
        )

        if not state['config'].check_access(client_dn, certname):
            abort(403, 'access denied')

        if api != 'metadatas':
            file_contents = None
            if part is None:
                fpath = certname_path
            else:
                fpath = os.path.join(certname_path, certversion, part)

                try:
                    with open(fpath, 'rb') as requested_f:
                        file_contents = requested_f.read()
                except OSError as ose:
                    app.logger.error(ose)
                    abort(503, 'unable to fulfill request')

                if api != 'metadata':
                    return flask.Response(file_contents, mimetype='application/octet-stream')

            return flask.Response(yaml.dump(get_file_metadata(fpath, file_contents,
                                                              state['config'].api['clients_root_directory'])),
                                  mimetype='text/yaml')

        metadatas = get_directory_metadata(certname, certname_path, state['config'].api['clients_root_directory'],
                                           valid_parts)
        return flask.Response(yaml.dump(metadatas), mimetype='text/yaml')

    return app


if __name__ == '__main__':
    create_app().run()
