"""
Main module of Quart. Contains the main
function that calls the other functions in the following order:
 - qualys_quart module to download the reports via the Qualys API
 - xml_parser_quart module to parse the reports (they are
 downloaded as XML in strings)
 - jira_quart to update/create tickets on JIRA through the JIRA API and
 jira python.
"""
import argparse
import logging
import sys
import xml.dom.minidom
from logging.handlers import RotatingFileHandler

from requests import ConnectionError, HTTPError, Timeout, TooManyRedirects
from confiture import Confiture
from confiture.parser import ParsingError
from confiture.schema import ValidationError
from confiture.schema.containers import Choice, Section, Value
from confiture.schema.types import Integer, String
from jira import JIRAError

from quart.jira_quart import update_jira
from quart.qualys_quart import get_qualys_reports
from quart.xml_parser_quart import (fusion_vulnerability_dictionaries,
                                    get_vulnerability_dictionary_from_xml)

LOGGER = logging.getLogger(__name__)


class FilterSection(Section):
    min_severity = Choice(
        {'1': 1, '2': 2, '3': 3, '4': 4, '5': 5},
        default=3,
        argparse_help='Minimum severity for potential/confirmed '
                      'vulnerabilities.',
        argparse_names=['-s', '--min-severity']
    )
    info_gathering = Choice(
        {'yes': True, 'no': False},
        default=False,
        argparse_help='Pass information gathering vulnerabilities '
                      'to JIRA or ignore them.',
        argparse_names=['-i', '--info-gathering']
    )
    min_info_severity = Choice(
        {'1': 1, '2': 2, '3': 3},
        default=3,
        argparse_help='Minimum severity for information gathering '
                      'vulnerabilities.',
        argparse_names=['-mis', '--min-info_severity']
    )


class JiraSection(Section):
    url = Value(
        String(),
        argparse_help='Jira URL.',
        argparse_names=['-jurl', '--jira-url']
    )
    user = Value(
        String(),
        argparse_help='Jira username.',
        argparse_names=['-juser', '--jira-user']
    )
    password = Value(
        String(),
        argparse_help='Jira password.',
        argparse_names=['-jpass', '--jira-password']
    )
    key = Value(
        String(),
        argparse_help='Key of the Jira project where Quart will create '
                      'Jira issues.',
        argparse_names=['-jkey', '--jira-key']
    )
    custom_field = Value(
        Integer(),
        default=None,
        argparse_help='QID Jira custom_field ID. Ignore if no custom field'
                      'is configured.',
        argparse_names=['-cf', '--custom-field']
    )
    critical_min_sev = Choice(
        {'1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6},
        default=5,
        argparse_help='Set the minimum severity for a vulnerability to create '
                      'a critical issue.',
        argparse_names=['-cs', '--critical-severity']
    )
    major_min_sev = Choice(
        {'1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6},
        default=3,
        argparse_help='Set the minimum severity for a vulnerability to create '
                      'a critical issue.',
        argparse_names=['-ms', '--minimum-severity']
    )
    due_date = Choice(
        {'yes': True, 'no': False},
        default=False,
        argparse_help='Set due dates in Jira issues on/off.',
        argparse_names=['-d', '--due-dates']
    )
    critical_eta = Value(
        Integer(),
        default=1,
        argparse_help='Set the due date in days for critical issues.',
        argparse_names=['-ce', '--critical-eta']
    )
    major_eta = Value(
        Integer(),
        default=3,
        argparse_help='Set the due date in days for major issues.',
        argparse_names=['-me', '--major-eta']
    )
    low_eta = Value(
        Integer(),
        default=7,
        argparse_help='Set the due date in days for critical issues.',
        argparse_names=['-le', '--low-eta']
    )


class QualysSection(Section):
    url = Value(
        String(),
        argparse_help='Qualys URL',
        argparse_names=['-qurl', '--qualys-url']
    )
    user = Value(
        String(),
        argparse_help='Qualys username.',
        argparse_names=['-quser', '--qualys-username']
    )
    password = Value(
        String(),
        argparse_help='Qualys password.',
        argparse_names=['-qpass', '--qualys-password']
    )
    scan_title_hook = Value(
        String(),
        default='',
        argparse_help='String required in Qualys vulnerability title scans '
                      'for Quart to download it. Empty string for no '
                      'requirements',
        argparse_names=['-st', '--scan-title']
    )


class Config(Section):
    filter = FilterSection()
    jira = JiraSection()
    qualys = QualysSection()
    logging = Choice(
        {'silent': 'critical', 'normal': 'info', 'verbose': 'debug'},
        default='info',
        argparse_help='Set verbosity.',
        argparse_names=['-v', '--verbosity']
    )
    term_out = Choice(
        {'yes': True, 'no': False},
        default=True,
        argparse_help='Set output to terminal on/off.',
        argparse_names=['-c', '--console']
    )
    monitoring_log = Value(
        String(),
        default='',
        argparse_help='Set monitoring log path. Default is off.',
        argparse_names=['-m', '--monitoring']
    )
    syslog = Choice(
        {'yes': True, 'no': False},
        default=True,
        argparse_help='Set syslog output on/off.',
        argparse_names=['-sy', '--syslog']
    )
    syslog_verbosity = Choice(
        {'normal': 'info', 'verbose': 'debug'},
        default='info',
        argparse_help='Set syslog verbosity.',
        argparse_names=['-sv', '--syslog-verbosity']
    )


def get_configuration():
    """
    Get configuration from quart_config.init and CLI arguments.
    :return: confiture object
    """
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--config_path', default='etc/quart_config.conf')
    schema = Config()
    schema.populate_argparse(arg_parser)
    args = arg_parser.parse_args()
    config = Confiture.from_filename(args.config_path, schema=schema).\
        parse()
    return config


def display_config(config):
    """
    Print the configuration settings of Quart.
    :param config: confiture object that contains the configuration of Quart.
    """
    LOGGER.debug('min_severity: %d',
                 config.subsection('filter').get('min_severity'))
    LOGGER.debug('info_gathering: %r',
                 config.subsection('filter').get('info_gathering'))
    LOGGER.debug('min_severity: %d',
                 config.subsection('filter').get('min_info_severity'))
    LOGGER.debug('JIRA URL: %s', config.subsection('jira').get('url'))
    LOGGER.debug('JIRA user: %s', config.subsection('jira').get('user'))
    LOGGER.debug('JIRA password: %s',
                 config.subsection('jira').get('password'))
    LOGGER.debug('JIRA key: %s', config.subsection('jira').get('key'))
    LOGGER.debug('JIRA custom QID field ID: %r',
                 config.subsection('jira').get('custom_field'))
    LOGGER.debug('JIRA critical issue min severity: %d',
                 config.subsection('jira').get('critical_min_sev'))
    LOGGER.debug('JIRA critical issue ETA (days): %d',
                 config.subsection('jira').get('critical_eta'))
    LOGGER.debug('JIRA major issue min severity: %d',
                 config.subsection('jira').get('major_min_sev'))
    LOGGER.debug('JIRA issue due date configuration: %d',
                 config.subsection('jira').get('due_date'))
    LOGGER.debug('JIRA major issue ETA (days): %d',
                 config.subsection('jira').get('major_eta'))
    LOGGER.debug('JIRA low issue ETA (days): %d',
                 config.subsection('jira').get('low_eta'))
    LOGGER.debug('Qualys URL: %s', config.subsection('qualys').get('url'))
    LOGGER.debug('Qualys user: %s', config.subsection('qualys').get('user'))
    LOGGER.debug('Qualys password: %s',
                 config.subsection('qualys').get('password'))
    LOGGER.debug('Qualys scan title hook: %s',
                 config.subsection('qualys').get('scan_title_hook'))
    LOGGER.debug('Logging level: %s', config.get('logging'))
    LOGGER.debug('Terminal output: %r', config.get('term_out'))
    LOGGER.debug('Monitoring log: %r', config.get('monitoring_log'))
    LOGGER.debug('Syslog: %r', config.get('syslog'))
    LOGGER.debug('Syslog verbosity: %s', config.get('syslog_verbosity'))


def check_config_consistency(config):
    """
    Looks at some configuration parameters to make sure they make sense.
    :param config: confiture configuration object
    :return: True or False
    """
    if config.subsection('jira').get('critical_eta') < 0 or \
        config.subsection('jira').get('major_eta') < 0 or \
        config.subsection('jira').get('low_eta') < 0:
        LOGGER.critical('critical_eta, major_eta, and low_eta should '
                        'be positive integers.')
        return False

    if config.subsection('jira').get('critical_min_sev') == 6:
        LOGGER.warning('Jira critical priority issue creation '
                       'disabled for Quart.')

    if config.subsection('jira').get('major_min_sev') == 6:
        LOGGER.warning('Jira major priority issue '
                       'creation disabled for Quart.')

    if config.subsection('jira').get('critical_min_sev') <= \
        config.subsection('jira').get('major_min_sev'):
        LOGGER.warning('critical_min_sev is lower or equal to major_min_sev')

    return True


def main():
    """
    Main function of quart
    :return: None
    """
    root_logger = logging.getLogger('quart')
    root_logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(name)-12s %'
                                  '(levelname)-8s %(message)s')

    try:
        config = get_configuration()
    except (IOError, ValidationError, ParsingError) as err:
        sys.exit('Error parsing conf file')

    if sys.stdout.isatty() and config.get('term_out'):
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(logging.INFO)

        if config.get('logging') == 'critical':
            print 'CRITICAL'
            stream_handler.setLevel(logging.CRITICAL)

        if config.get('logging') == 'debug':
            print 'DEBUG'
            stream_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(stream_handler)

    if config.get('syslog'):
        syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
        syslog_handler.setFormatter(formatter)

        if config.get('syslog_verbosity') == 'debug':
            syslog_handler.setLevel(logging.DEBUG)

        else:
            syslog_handler.setLevel(logging.INFO)

        root_logger.addHandler(syslog_handler)

    try:
        display_config(config)
    except AttributeError:
        LOGGER.exception('A complete configuration is needed '
                         'for Quart to run.')
        sys.exit(1)

    # Check the configuration has consistent parameters.
    if not check_config_consistency(config):
        sys.exit(1)

    LOGGER.info('Quart start')

    try:
        # List of strings of reports in XML formats
        report_list = get_qualys_reports(config)

    except (ConnectionError, HTTPError, Timeout, TooManyRedirects,
            IOError, ValueError) as err:
        LOGGER.exception('Error encountered trying to '
                         'connect to Qualys API: %s', err)
        sys.exit(1)

    try:
        vulnerability_dictionary = {}
        LOGGER.debug('Parsing reports.')

        for report in report_list:
            root = xml.dom.minidom.parseString(report.content).\
                documentElement
            temp_vul_dict = \
                get_vulnerability_dictionary_from_xml(root)
            fusion_vulnerability_dictionaries(vulnerability_dictionary,
                                              temp_vul_dict)

        LOGGER.debug('Reports parsed successfully.')
    except (TypeError, AttributeError) as err:
        LOGGER.exception('Error while parsing reports: %s', err)
        sys.exit(1)

    try:
        jira_counter = update_jira(vulnerability_dictionary, config)
        LOGGER.debug('Total vulnerabilities detected: %d',
                     len(vulnerability_dictionary))
        LOGGER.debug('Total vulnerabilities passed on to JIRA: %d',
                     jira_counter)
    except JIRAError:
        LOGGER.exception('Error encountered when working with Jira: %s',
                         JIRAError)
        sys.exit(1)

    # If configured: set up monitoring log and log successful Quart run.
    if config.get('monitoring_log'):
        monitor_handler = logging.handlers.RotatingFileHandler(
            config.get('monitoring_log'),
            maxBytes=10000,
            backupCount=2,
            encoding=None,
            delay=0
        )
        monitor_handler.setFormatter(formatter)
        monitor_handler.setLevel(logging.DEBUG)
        LOGGER.addHandler(monitor_handler)

    LOGGER.info(
        'Quart done - Total vulns: %d | Passed: %d',
        len(vulnerability_dictionary),
        jira_counter
    )
