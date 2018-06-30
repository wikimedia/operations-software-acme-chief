# Central certificates service
# Alex Monk <krenair@gmail.com>, May/June 2018
import collections
import flask
import hashlib
import os
import signal
import subprocess
import tempfile
import threading
import time
import traceback
import yaml

import acme_tiny

config = None
authorised_hosts = None


def sighup_handler(*args):
    global config
    global authorised_hosts
    with open('/etc/certcentral/config.yaml') as f:
        config = yaml.safe_load(f)
    temp_authorised_hosts = collections.defaultdict(list)
    for fname in os.listdir('/etc/certcentral/conf.d'):
        with open('/etc/certcentral/conf.d/{}'.format(fname)) as f:
            d = yaml.safe_load(f)
            temp_authorised_hosts[d['certname']].append(d['hostname'])
    authorised_hosts = temp_authorised_hosts


signal.signal(signal.SIGHUP, sighup_handler)
sighup_handler()


# some of this is borrowed from acme-setup
def check_output_errtext(args):
    """exec args, returns (stdout,stderr). raises on rv!=0 w/ stderr in msg"""
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (p_out, p_err) = p.communicate()
    if p.returncode != 0:
        raise Exception("Command >>%s<< failed, exit code %i, stderr:\n%s"
                        % (" ".join(args), p.returncode, p_err))
    return (p_out, p_err)


ec_prime256v1_paramfile = '/etc/certcentral/prime256v1.ecparams'
check_output_errtext(['openssl', 'ecparam', '-name', 'prime256v1', '-out', ec_prime256v1_paramfile])
key_types = {
    'rsa-2048': {
        'algorithm': 'rsa',
        'options': {'rsa_keygen_bits': '2048'},
        'req-newkey': '2048'
    },
    'ec-prime256v1': {
        'algorithm': 'ec',
        'options': {'ec_paramgen_curve': 'prime256v1'},
        'req-newkey': ec_prime256v1_paramfile
    }
}


def certificate_management():
    # TODO: make this go through certs and renew where necessary
    global config
    check_output_errtext(['openssl', 'genrsa', '-out', '/etc/certcentral/acct.key', '2048'])
    # init everything as snakeoil certs
    for cert_id, cert_details in config.items():
        for key_type_id, key_type_details in key_types.items():
            public_key_filename = '{}.{}.public.pem'.format(cert_id, key_type_id)
            public_key_file = os.path.join('/etc/certcentral/live_certs', public_key_filename)
            private_key_filename = '{}.{}.private.pem'.format(cert_id, key_type_id)
            private_key_file = os.path.join('/etc/certcentral/live_certs', private_key_filename)
            if not os.path.exists(public_key_file) or not os.path.exists(private_key_file):
                newkey_param = '{}:{}'.format(
                    key_type_details['algorithm'],
                    key_type_details['req-newkey']
                )
                check_output_errtext([
                    "openssl", "req",
                    "-nodes",
                    "-new",
                    "-newkey", newkey_param,
                    "-x509",
                    "-keyout", private_key_file,
                    "-out", public_key_file,
                    "-subj", "/CN=Snakeoil cert"
                ])

    have_certs = set()
    while True:
        for cert_id, cert_details in config.items():
            for key_type_id, key_type_details in key_types.items():
                if (cert_id, key_type_id) in have_certs:
                    continue
                # some of this is borrowed from acme-setup too
                temp_private_key = tempfile.NamedTemporaryFile()
                keygen_cmd = [
                    'openssl', 'genpkey',
                    '-out', temp_private_key.name,
                    '-algorithm', key_type_details['algorithm']
                ]
                for opt_key, opt_val in key_type_details['options'].items():
                    keygen_cmd.append('-pkeyopt')
                    keygen_cmd.append('{}:{}'.format(opt_key, opt_val))
                check_output_errtext(keygen_cmd)
                csr_filename = '{}.{}.csr.pem'.format(cert_id, key_type_id)
                csr = os.path.join('/etc/certcentral/csrs', csr_filename)
                with tempfile.NamedTemporaryFile() as cfg:
                    cfg.write('\n'.join([
                        '[req]',
                        'distinguished_name=req_dn',
                        'req_extensions=SAN',
                        'prompt=no',
                        '[req_dn]',
                        'commonName=' + cert_details['CN'],
                        '[SAN]',
                        'subjectAltName=' + ','.join(['DNS:' + s for s in cert_details['SNI']]),
                    ]).encode('utf-8'))
                    cfg.flush()
                    check_output_errtext([
                        'openssl', 'req',
                        '-new',
                        '-sha256',
                        '-out', csr,
                        '-key', temp_private_key.name,
                        '-config', cfg.name
                    ])
                # TODO: do ACME v2 DNS wildcard requests and write challenges to
                # dns_challenges/{domain}
                try:
                    # TODO: make this check for /.well-known/acme-challenge file on % of authorised
                    # hosts
                    signedCert = acme_tiny.get_crt(
                        '/etc/certcentral/acct.key',
                        csr,
                        '/etc/certcentral/http_challenges',
                        CA='https://acme-staging.api.letsencrypt.org'
                    )

                    public_cert_path = os.path.join(
                        '/etc/certcentral/live_certs',
                        '{}.{}.public.pem'.format(cert_id, key_type_id)
                    )
                    with open(public_cert_path, 'w+b') as f:
                        f.write(signedCert.encode('utf-8'))

                    private_key_path = os.path.join(
                        '/etc/certcentral/live_certs',
                        '{}.{}.private.pem'.format(cert_id, key_type_id)
                    )
                    with open(private_key_path, 'w+b') as f:
                        f.write(temp_private_key.read())

                    have_certs.update([(cert_id, key_type_id)])
                except:
                    traceback.print_exc()
                temp_private_key.close()
            time.sleep(5)


threading.Thread(target=certificate_management, name="Issue and renew certificates").start()
app = flask.Flask(__name__)


@app.route("/certs/<certname>/<part>")
@app.route("/puppet/v3/file_<api>/acmedata/<certname>/<part>")
def get_certs(certname=None, part=None, api=None):
    global config

    if api is not None and api not in ['metadata', 'content']:
        return 'invalid puppet API call', 400

    valid_parts = []
    for key_type_id in key_types.keys():
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

    if certname not in config:
        return 'no such certname', 404

    if client_dn not in authorised_hosts[certname]:
        return 'gtfo', 403

    fpath = '/etc/certcentral/live_certs/{}.{}'.format(certname, part)
    with open(fpath, 'rb') as f:
        file_contents = f.read()

    assert flask.request.args.get('environment') == 'production'
    if api == 'metadata':
        assert flask.request.args.get('checksum_type') == 'md5'
        assert flask.request.args.get('links') == 'manage'
        assert flask.request.args.get('source_permissions') == 'ignore'
        stat_ret = os.stat(fpath)
        d = {
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
        return flask.Response(yaml.dump(d), mimetype='text/yaml')
    else:
        return file_contents


if __name__ == '__main__':
    app.run()

