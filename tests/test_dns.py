import mock
import unittest

from acme_chief.dns import DEFAULT_DNS_TIMEOUT, DNSNoAnswerError, DNS_PORT, Resolver

class ResolverTest(unittest.TestCase):
    @mock.patch('dns.resolver.Resolver')
    def test_query(self, resolver_mock):
        test_cases = (
            {
                'query_record': 'TXT',
                'query_method': 'txt_query',
                'records': ['v=spf1 ip4:91.198.174.0/24 ip4:208.80.152.0/22 ~all']
            },
            {
                'query_record': 'CAA',
                'query_method': 'caa_query',
                'records': ['0 issue "digicert.com"',
                            '0 issue "globalsign.com"',
                            '0 issue "letsencrypt.org"',
                            '0 iodef "mailto:dns-admin@wikimedia.org"']
            },
            {
                'query_record': 'NS',
                'query_method': 'ns_query',
                'records': ['ns0.wikimedia.org.',
                            'ns1.wikimedia.org.',
                            'ns2.wikimedia.org.']
            },
        )
        for test_case in test_cases:
            with self.subTest(query_record=test_case['query_record']):
                resolver_mock.reset_mock()
                rrset_mocks = []
                for record in test_case['records']:
                    rrset_mock = mock.MagicMock()
                    rrset_mock.to_text.return_value = record
                    rrset_mocks.append(rrset_mock)
                answer_mock = mock.MagicMock()
                answer_mock.rrset = rrset_mocks
                resolver_mock.return_value.query.return_value = answer_mock
                resolver = Resolver(nameservers=['127.0.0.1'], timeout=DEFAULT_DNS_TIMEOUT)
                query_method = getattr(resolver, test_case['query_method'])
                records = query_method('_acme-challenge.tests.wmflab.org')
                self.assertEqual(records, test_case['records'])
                resolver_instance = resolver_mock.return_value
                self.assertEqual(resolver_instance.port, DNS_PORT)
                self.assertEqual(resolver_instance.timeout, DEFAULT_DNS_TIMEOUT)
                self.assertEqual(resolver_instance.lifetime, DEFAULT_DNS_TIMEOUT)
                self.assertEqual(resolver_instance.nameservers, ['127.0.0.1'])
                resolver_instance.query.assert_called_once_with('_acme-challenge.tests.wmflab.org',
                                                                rdtype=test_case['query_record'])

    @mock.patch('dns.resolver.Resolver')
    def test_get_record(self, resolver_mock):
        test_cases = (
            {
                'requested_name': 'www.wmflabs.org',
                'record_type': 'NS',
                'matching_name': 'wmflabs.org.',
                'records': ['ns0.wikimedia.org.', 'ns1.wikimedia.org.', 'ns2.wikimedia.org.'],
            },
            {
                'requested_name': 'www.wmflabs.org.',
                'record_type': 'CAA',
                'matching_name': 'www.wmflabs.org.',
                'records': ['0 issue "digicert.com"',
                            '0 issue "globalsign.com"',
                            '0 issue "letsencrypt.org"',
                            '0 iodef "mailto:dns-admin@wikimedia.org"'],
            },
            {
                'requested_name': 'www.wmflabs.org',
                'record_type': 'NS',
                'matching_name': None,
                'records': None,
            },
            {
                'requested_name': 'www.wmflabs.org',
                'record_type': 'CAA',
                'matching_name': None,
                'records': None,
            },
        )

        for test_case in test_cases:
            with self.subTest(test_case=test_case):
                resolver_mock.reset_mock()
                requested_name = test_case['requested_name']
                if not requested_name.endswith('.'):
                    requested_name += '.'
                requested_name_parts = requested_name.split('.')

                expected_queries = []
                for i in range(0, len(requested_name_parts)-2):
                    candidate = '.'.join(requested_name_parts[i:])
                    expected_queries.append(candidate)
                    if candidate == test_case['matching_name']:
                        break

                answer_mocks = []
                for expected_query in expected_queries:
                    if expected_query != test_case['matching_name']:
                        answer_mocks.append(DNSNoAnswerError)
                        continue

                    answer_mock = mock.MagicMock()
                    rrset_mocks = []
                    for record in test_case['records']:
                        rrset_mock = mock.MagicMock()
                        rrset_mock.to_text.return_value = record
                        rrset_mocks.append(rrset_mock)
                    answer_mock = mock.MagicMock()
                    answer_mock.rrset = rrset_mocks
                    answer_mocks.append(answer_mock)

                resolver_mock.return_value.query.side_effect = answer_mocks
                resolver = Resolver(nameservers=['127.0.0.1'], timeout=DEFAULT_DNS_TIMEOUT)
                records = resolver.get_record(test_case['requested_name'], test_case['record_type'])
                self.assertEqual(records, test_case['records'])
                self.assertEqual(len(expected_queries), len(resolver_mock.return_value.query.mock_calls))
                expected_query_calls = []
                for expected_query in expected_queries:
                    expected_query_calls.append(mock.call(expected_query, rdtype=test_case['record_type']))
                resolver_mock.return_value.query.assert_has_calls(expected_query_calls)
