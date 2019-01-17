"""
Module containing configuration handling classes

Alex Monk <krenair@gmail.com> 2018
Valentin Gutierrez <vgutierrez@wikimedia.org> 2018-2019
"""

import collections
import datetime
import logging
import os
import re

import yaml

from acme_chief.acme_requests import ACMEChallengeType

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

# default values that can be customized via the config file. Check the README for a valid example
DEFAULT_DNS_ZONE_UPDATE_CMD = '/bin/echo'
DEFAULT_DNS_ZONE_UPDATE_CMD_TIMEOUT = 60.0

DEFAULT_CERTIFICATE_STAGING_TIME = 3600

DEFAULT_API_CLIENTS_ROOT_DIRECTORY = '/etc/acmecerts'


class ACMEChiefConfig:
    """Class representing ACMEChief configuration"""
    def __init__(self, *, accounts, certificates, default_account,
                 authorized_hosts, authorized_regexes, challenges, api):
        self.accounts = accounts
        self.certificates = certificates
        self.default_account = default_account
        self.authorized_hosts = authorized_hosts
        self.authorized_regexes = authorized_regexes
        self.challenges = {}
        self.api = api

        for challenge_type, challenge_config in challenges.items():
            if challenge_type == 'dns-01':
                if not ('zone_update_cmd' in challenge_config and os.access(challenge_config['zone_update_cmd'],
                                                                            os.X_OK)):
                    logger.warning("Missing/invalid DNS zone updater CMD, using the default one: %s",
                                   DEFAULT_DNS_ZONE_UPDATE_CMD)
                    challenge_config['zone_update_cmd'] = DEFAULT_DNS_ZONE_UPDATE_CMD

                try:
                    challenge_config['zone_update_cmd_timeout'] = float(challenge_config['zone_update_cmd_timeout'])
                except (KeyError, ValueError):
                    logger.warning("Missing/invalid DNS zone updater CMD timeout, using the default one: %.2f",
                                   DEFAULT_DNS_ZONE_UPDATE_CMD_TIMEOUT)
                    challenge_config['zone_update_cmd_timeout'] = DEFAULT_DNS_ZONE_UPDATE_CMD_TIMEOUT

                self.challenges[ACMEChallengeType.DNS01] = challenge_config
            elif challenge_type == 'http-01':
                self.challenges[ACMEChallengeType.HTTP01] = challenge_config
            else:
                logger.warning("Unexpected challenge type found in configuration: %s", challenge_type)

        if ACMEChallengeType.DNS01 not in self.challenges:
            logger.warning('Missing dns-01 challenge configuration')

    @staticmethod
    def load(file_name, confd_path=None):  # pylint: disable=too-many-locals
        """Load a config from the specified file_name and an optional conf.d path"""
        logger.debug("Loading config file: %s", file_name)
        if confd_path is None:
            confd_path = os.path.dirname(file_name)

        with open(file_name) as config_file:
            config = yaml.safe_load(config_file)

        default_account = ACMEChiefConfig._get_default_account(config['accounts'])

        authorized_hosts = collections.defaultdict(set)
        authorized_regexes = collections.defaultdict(set)

        # TODO: Consider getting rid of conf.d/ support in the future
        for fname in os.listdir(confd_path):
            file_path = os.path.join(confd_path, fname)
            logger.debug("Loading config file: %s", file_path)
            with open(file_path) as conf_f:
                conf_data = yaml.safe_load(conf_f)
                if conf_data['certname'] not in config['certificates']:
                    logger.warning("Certificate %s referenced on %s not found in general config",
                                   conf_data['certname'], file_path)
                    continue
                authorized_hosts[conf_data['certname']].add(conf_data['hostname'])

        for cert_name, cert_config in config['certificates'].items():
            staging_time_seconds = cert_config.get('staging_time', DEFAULT_CERTIFICATE_STAGING_TIME)
            try:
                cert_config['staging_time'] = datetime.timedelta(seconds=int(staging_time_seconds))
            except TypeError:
                logger.warning("Ignoring invalid staging time %s for certificate %s. Using the default one: %s",
                               staging_time_seconds, cert_name, DEFAULT_CERTIFICATE_STAGING_TIME)
                cert_config['staging_time'] = datetime.timedelta(seconds=DEFAULT_CERTIFICATE_STAGING_TIME)

            if cert_config['CN'] not in cert_config['SNI']:
                cert_config['SNI'].append(cert_config['CN'])
                logger.warning("Appending CN to SNI list for certificate %s", cert_name)

            if 'authorized_hosts' in cert_config:
                authorized_hosts[cert_name].update(cert_config['authorized_hosts'])
            if 'authorized_regexes' in cert_config:
                for regex in cert_config['authorized_regexes']:
                    try:
                        authorized_regexes[cert_name].add(re.compile(regex))
                    except (re.error, TypeError):
                        logger.warning("Ignoring invalid authorized regex %s for certificate %s", regex, cert_name)
                        continue

        api = config.get('api', {'clients_root_directory': DEFAULT_API_CLIENTS_ROOT_DIRECTORY})

        return ACMEChiefConfig(accounts=config['accounts'],
                               certificates=config['certificates'],
                               default_account=default_account,
                               authorized_hosts=dict(authorized_hosts),
                               authorized_regexes=dict(authorized_regexes),
                               challenges=config['challenges'],
                               api=api)

    @staticmethod
    def _get_default_account(accounts):
        for account in accounts:
            if 'default' in account and account['default'] is True:
                return account['id']

        return accounts[0]['id']

    def check_access(self, hostname, cert_name):
        """Returns True if hostname is allowed to fetch the specified certificate. False otherwise"""

        if hostname in self.authorized_hosts.get(cert_name, ()):
            return True

        try:
            for regex in self.authorized_regexes[cert_name]:
                if regex.fullmatch(hostname) is not None:
                    return True
        except (KeyError, TypeError, re.error):
            return False

        return False