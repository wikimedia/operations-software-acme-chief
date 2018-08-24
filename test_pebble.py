import http.server
import json
import os
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse

import dnslib
import requests

from x509 import RSAPrivateKey, SelfSignedCertificate

PEBBLE_CMD_FLAGS = ['-strict=false']
PEBBLE_ENV_VARS = {
    'PATH': os.environ.get('PATH'),
    'PEBBLE_VA_ALWAYS_VALID': '1',
    'PEBBLE_WFE_NONCEREJECT': '0',
    'PEBBLE_VA_SLEEPTIME': '5',
}

LISTEN_ADDRESS = '127.0.0.1'
PEBBLE_LISTEN_ADDRESS = '127.0.0.1:14000'

def tcp_wait(port, timeout=3):
    step = 0
    delay = 0.1  # seconds
    socket_timeout = 1  # seconds
    connected = False
    while step < timeout:
        try:
            s = socket.socket()
            s.settimeout(socket_timeout)
            s.connect((LISTEN_ADDRESS, int(port)))
            connected = True
            break
        except (ConnectionAbortedError, ConnectionRefusedError):
            step = step + delay
            time.sleep(delay)
        finally:
            s.close()

    if not connected:
        raise TimeoutError(
            'Could not connect to port %s after %s seconds' % (port, timeout))


class HTTPProxyHandler(http.server.BaseHTTPRequestHandler):
    """Pretty simple HTTP proxy server used to trick requests into connecting to
       our http challenge server without altering production code
    """
    timeout = 3.0
    server = LISTEN_ADDRESS
    port = 8080

    def do_GET(self):
        request_url = urlparse(self.path)

        url = urlunparse((
            'http',
            "{}:{}".format(HTTPProxyHandler.server, HTTPProxyHandler.port),
            request_url.path,
            '',
            '',
            ''))
        response = requests.get(url, stream=True, proxies=None, timeout=HTTPProxyHandler.timeout)
        self.send_response(response.status_code)
        for header_name, header_value in response.headers.items():
            self.send_header(header_name, header_value)
        self.end_headers()

        self.wfile.write(response.content)


class HTTP01ChallengeHandler(http.server.BaseHTTPRequestHandler):
    challenges_path = '/tmp'

    def do_GET(self):
        file_path = os.path.join(HTTP01ChallengeHandler.challenges_path, self.path.split('/')[-1])

        try:
            challenge_file = open(file_path, 'rb')
        except OSError:
            self.send_error(404, 'File not found')
            return

        self.send_response(200)
        challenge_stat = os.fstat(challenge_file.fileno())
        self.send_header('Content-Length', str(challenge_stat.st_size))
        self.end_headers()
        shutil.copyfileobj(challenge_file, self.wfile)

        challenge_file.close()

class BaseDNSRequestHandler(socketserver.BaseRequestHandler):
    challenges_path = '/tmp'

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

    def handle(self):
        try:
            data = self.get_data()
            query = dnslib.DNSRecord.parse(data)
            reply = query.reply()
            answers = []

            if reply.get_q().qtype == dnslib.QTYPE.TXT:
                try:
                    challenge_files = os.listdir(BaseDNSRequestHandler.challenges_path)
                    for challenge_file in challenge_files:
                        if challenge_file.startswith(str(reply.get_q().qname).strip('.')):
                            with open(os.path.join(BaseDNSRequestHandler.challenges_path,
                                                   challenge_file), 'r') as challenge_data:
                                answers.append(dnslib.RR(rname=reply.get_q().qname,
                                                         rtype=reply.get_q().qtype,
                                                         ttl=60,
                                                         rdata=dnslib.TXT(challenge_data.read().strip())))
                except OSError:
                    pass
            else:
                answers.append(dnslib.RR(rname=reply.get_q().qname,
                                         ttl=60,
                                         rdata=dnslib.A(LISTEN_ADDRESS)))

            for answer in answers:
                reply.add_answer(answer)
            self.send_data(reply.pack())
        except Exception:
            pass


class BasePebbleIntegrationTest(unittest.TestCase):
    """
    The integration tests expect to find pebble in your PATH
    it can be installed with go get -u github.com/letsencrypt/pebble/...
    It will spawn a DNS server and a HTTP server if needed
    """
    @staticmethod
    def _generate_pebble_config(config_dir, http_port):
        cert_path = os.path.join(config_dir, 'pebble.key')
        key_path = os.path.join(config_dir, 'pebble.pem')
        config_path = os.path.join(config_dir, 'pebble.json')
        key = RSAPrivateKey()
        key.generate()
        key.save(key_path)

        cert = SelfSignedCertificate(
            private_key=key,
            common_name='localhost',
            sans=[
                '127.0.0.1',
                'pebble',
                'localhost',
            ],
            from_date=datetime.utcnow(),
            until_date=datetime.utcnow() + timedelta(days=1),
        )
        cert.save(cert_path)

        config = {
            'pebble': {
                'listenAddress': PEBBLE_LISTEN_ADDRESS,
                'certificate': cert_path,
                'privateKey': key_path,
                'httpPort': http_port,  # only used when PEBBLE_VA_ALWAYS_VALID=0
                'tlsPort': 5001,        # only used when PEBBLE_VA_ALWAYS_VALID=0
            }
        }
        with open(config_path, 'w') as config_file:
            json.dump(config, config_file)
        return config_path

    @classmethod
    def setUpClass(cls, **kwargs):
        super().setUpClass()
        cls.valid_challenges = kwargs.get('valid_challenges', False)

        cls.pebble_tempdir = tempfile.TemporaryDirectory()

        env_vars = PEBBLE_ENV_VARS
        cmd_flags = PEBBLE_CMD_FLAGS
        http_port = 5002

        if cls.valid_challenges:
            cls.dns_server = socketserver.ThreadingUDPServer((LISTEN_ADDRESS, 0), BaseDNSRequestHandler)
            cls.dns_server_thread = threading.Thread(target=cls.dns_server.serve_forever)
            cls.dns_server_thread.start()
            cls.http_server = socketserver.ThreadingTCPServer((LISTEN_ADDRESS, 0), HTTP01ChallengeHandler)
            cls.http_server_thread = threading.Thread(target=cls.http_server.serve_forever)
            cls.http_server_thread.start()
            cls.proxy_server = socketserver.ThreadingTCPServer((LISTEN_ADDRESS, 0), HTTPProxyHandler)
            cls.proxy_server_thread = threading.Thread(target=cls.proxy_server.serve_forever)
            cls.proxy_server_thread.start()

            _, dns_port = cls.dns_server.server_address
            _, http_port = cls.http_server.server_address
            _, proxy_port = cls.proxy_server.server_address

            tcp_wait(http_port)
            tcp_wait(proxy_port)

            HTTPProxyHandler.port = http_port
            env_vars['PEBBLE_VA_ALWAYS_VALID'] = '0'
            env_vars['PEBBLE_VA_NOSLEEP'] = '1'
            cmd_flags.append('-dnsserver={}:{}'.format(LISTEN_ADDRESS, dns_port))

        config_path = cls._generate_pebble_config(cls.pebble_tempdir.name, http_port)
        log_dir = os.environ.get('LOG_DIR')  # set by the tox CI container
        if log_dir is None:
            cls.pebble_log = subprocess.DEVNULL
        else:
            cls.pebble_log = open(os.path.join(log_dir, 'pebble.log'), 'a')

        cls.pebble_instance = subprocess.Popen(['pebble', '-config=' + config_path] + cmd_flags,
                                               env=env_vars,
                                               stdout=cls.pebble_log,
                                               stderr=subprocess.DEVNULL)
        tcp_wait(PEBBLE_LISTEN_ADDRESS.split(':')[-1])

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.pebble_instance.terminate()
        try:
            cls.pebble_instance.wait(2)
        except subprocess.TimeoutExpired:
            cls.pebble_instance.kill()
        finally:
            if cls.pebble_log is not subprocess.DEVNULL:
                cls.pebble_log.close()
            cls.pebble_tempdir.cleanup()

        if cls.valid_challenges:
            cls.dns_server.shutdown()
            cls.dns_server.server_close()
            cls.dns_server_thread.join()
            cls.http_server.shutdown()
            cls.http_server.server_close()
            cls.http_server_thread.join()
            cls.proxy_server.shutdown()
            cls.proxy_server.server_close()
            cls.proxy_server_thread.join()
