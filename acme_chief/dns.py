"""
Module containing DNS query helpers

Valentin Gutierrez <vgutierrez@wikimedia.org> 2019
"""
import socket

from dns import resolver
from dns.exception import Timeout

DEFAULT_DNS_TIMEOUT = 2
DEFAULT_DNS_PORT = 53


class DNSError(Exception):
    """Generic DNS Error"""


class DNSFailedQueryError(DNSError):
    """Unable to perform DNS query"""


class DNSNoAnswerError(DNSError):
    """Query performed successfully. No answer obtained"""


class Resolver:
    """Small DNS Resolver class that makes sure that sane options like timeouts and the proper DNS servers
       are being used"""
    def __init__(self, nameservers=None, timeout=DEFAULT_DNS_TIMEOUT, port=DEFAULT_DNS_PORT):
        self._resolver = resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
        self._resolver.port = port
        if nameservers is not None:
            try:
                self._resolver.nameservers = self.resolve_dns_servers(nameservers)
            except (socket.gaierror, UnicodeError):
                raise AttributeError('Invalid nameseservers specified: {}'.format(nameservers))

    @staticmethod
    def resolve_dns_servers(dns_servers):
        """Use system resolver to attempt to resolve DNS servers specified as hostnames"""
        ret = []
        for dns_server in dns_servers:
            addresses_info = socket.getaddrinfo(dns_server, 53, proto=socket.IPPROTO_UDP)
            for _, _, _, _, sockaddr in addresses_info:
                ret.append(sockaddr[0])

        return ret

    def _query(self, name, rdtype):
        try:
            answer = self._resolver.query(name, rdtype=rdtype)
        except (resolver.NXDOMAIN, resolver.YXDOMAIN, resolver.NoAnswer) as dnse:
            raise DNSNoAnswerError from dnse
        except (Timeout, resolver.NoNameservers) as dnse:
            raise DNSFailedQueryError from dnse

        ret = []
        for rrset in answer.rrset:
            if rdtype.upper() == 'TXT':
                ret.append(rrset.to_text().strip('"'))
            else:
                ret.append(rrset.to_text())

        return ret

    def txt_query(self, name):
        """Perform a TXT query. Returns a list of TXT records associated to the specified name"""
        return self._query(name, 'TXT')

    def caa_query(self, name):
        """Perform a CAA query. Returns a list of CAA records associated to the specified name"""
        return self._query(name, 'CAA')

    def ns_query(self, name):
        """Perform a NS query. Returns a list of NS records associated to the specified name"""
        return self._query(name, 'NS')

    def get_record(self, name, record_type):
        """Gets the most accurate record for the specified name"""
        if not name.endswith('.'):
            name += '.'

        parts = name.split('.')
        for i in range(0, len(parts)-2):
            candidate = '.'.join(parts[i:])
            try:
                return self._query(candidate, record_type)
            except DNSNoAnswerError:
                continue

        return None
