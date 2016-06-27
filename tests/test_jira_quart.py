import pytest

from jira import JIRA
from confiture.schema.types import String, Integer
from confiture.schema.containers import Choice, Value, Section
from confiture import Confiture

import quart.jira_quart

#Set up test configuration file
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
        default= None,
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
        argparse_names=['-v', '--verbosity  ']
    )
    term_out = Choice(
        {'yes': True, 'no': False},
        default=True,
        argparse_help='Set output to terminal on/off.',
        argparse_names=['-c', '--console']
    )
    syslog = Choice(
        {'yes': True, 'no': False },
        default=True,
        argparse_help='Set syslog output on/off.',
        argparse_names=['-sy', '--syslog']
    )
    ip = Value(
        String(),
        default='localhost',
        argparse_help='IP address where syslog are sent.',
        argparse_names=['-ip']
    )
    port = Value(
        Integer(),
        default=514,
        argparse_help='Port number where syslogs are sent.',
        argparse_names=['-p', '--port']
    )
    facility = Value(
        String(),
        default='user',
        argparse_help='Facility code for the syslog.',
        argparse_names=['-f', '--facility']
    )


schema = Config()
config = Confiture.from_filename(
    'test_ressources/tests_jira_quart_config.conf',
    schema=schema
    ).parse()
jira = JIRA(
        options={'server': config.subsection('jira').get('url')},
        basic_auth=(
            str(config.subsection('jira').get('user')),
            str(config.subsection('jira').get('password'))
        )
    )


#Test find_the_open_issue
#Get different issue types from Jira (needs regular updates
# for test to work)
canceled_issue = jira.issue('VUMA-511')
awaiting_validation = jira.issue('VUMA-512')
awaiting_fix = jira.issue('VUMA-513')
in_progress = jira.issue('VUMA-514')
more_info = jira.issue('VUMA-515')
done = jira.issue('VUMA-516')


@pytest.mark.parametrize('issue_list, result', (
    ([], None),
    ([canceled_issue], None),
    ([canceled_issue, awaiting_fix], awaiting_fix),
    ([awaiting_validation, canceled_issue], awaiting_validation),
    ([in_progress], in_progress),
    ([more_info], more_info),
    ([done], None)
))


def test_find_the_open_issue(issue_list, result):
    assert quart.jira_quart.find_the_open_issue(
        issue_list) == result


#Test is_issue_canceled
@pytest.mark.parametrize('issue_list, result', (
    ([], False),
    ([canceled_issue], True)
))


def test_is_issue_canceled(issue_list, result):
    assert quart.jira_quart.is_issue_canceled(
        issue_list) == result


#Test vulnerability_filter
VULN = [
    {
        'qid': '',
        'title': '',
        'category': 'Information gathering',
        'severity': 3
    },
    {
        'qid': '',
        'title': '',
        'category': 'Information gathering',
        'severity': 2
    },
    {
        'qid': '',
        'title': '',
        'category': '',
        'severity': 3
    },
    {
        'qid': '',
        'title': '',
        'category': '',
        'severity': 2
    }
]


@pytest.mark.parametrize('vulnerability, ticket_list, config, result', (
    (VULN[0], [], config, True),
    (VULN[1], [], config, False),
    (VULN[2], [], config, True),
    (VULN[2], [canceled_issue], config, False),
    (VULN[3], [], config, False)
))


def test_vulnerability_filter(vulnerability, ticket_list, config, result):
    assert quart.jira_quart.vulnerability_filter(
        vulnerability, ticket_list, config) == result
