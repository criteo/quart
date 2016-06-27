"""
This module deals with all the processes that involve Quart and JIRA:
- Getting JIRA issues
- Identifying issues that relate to each vulnerability
- Determine whether an issue should be created/updated
- Create/update issues
"""
import re
import datetime
import logging

from jira import JIRA


LOGGER = logging.getLogger(__name__)

ISSUE_DESCRIPTION = """
{{html}}
<u><b>Vulnerability Title:</b></u> {0}<br>
<u><b>QID:</b></u> {1}<br>
<u><b>Category:</b></u> {2}<br>
<u><b>Severity:</b></u> {3}/5 (/3 for information gathering category)<br>
<u><b>Affected IP(s):</b></u> {4}<br><br>
<p><u><b>Diagnosis:</b></u> {5}</p>
<p><u><b>Consequence:</b></u> {6}</p>
<p><u><b>Solution:</b></u> {7}</p><br>
<i>This issue was automatically created by Quart.</i>
{{html}}
"""

JQL_QUERY = "project={0} and creator={1}"


def update_jira(vulnerability_dictionary, config):
    """
    Feeds JIRA with issues based on the vulnerability dictionary.
    :param vulnerability_dictionary: dictionary of vulnerabilities
    :param config: confiture object that contains the quart configuration.
    :return: int, number of issues created/updated to Jira.
    """
    passed_vulnerabilities_counter = 0
    jira = JIRA(
        options={'server': config.subsection('jira').get('url')},
        basic_auth=(
            str(config.subsection('jira').get('user')),
            str(config.subsection('jira').get('password'))
        )
    )
    issue_list = get_quart_issue_list(jira, config)

    for vulnerability in vulnerability_dictionary:
        # Get all issues created by Quart on this vulnerability
        vulnerability_issues = get_vulnerability_issue_list(
            issue_list,
            vulnerability_dictionary[vulnerability]['qid'],
            config
        )
        # Issue creation filter to avoid creating unnecessary issues
        if vulnerability_filter(
                vulnerability_dictionary[vulnerability],
                vulnerability_issues,
                config
        ):
            verify_hostname(vulnerability_dictionary[vulnerability])
            # If no existing issues: create a new issue
            if not vulnerability_issues:
                new_issue = create_vulnerability_issue(
                    jira,
                    vulnerability_dictionary[vulnerability],
                    config
                )
                LOGGER.info(
                    'Created issue: %s for QID %s -> %s',
                    str(new_issue),
                    vulnerability_dictionary[vulnerability]['qid'],
                    vulnerability_dictionary[vulnerability]['title']
                )
                passed_vulnerabilities_counter += 1

            # Else update existing issues
            else:
                update_jira_issues(jira, vulnerability_issues,
                                   vulnerability_dictionary[vulnerability],
                                   config)
                passed_vulnerabilities_counter += 1

        else:
            LOGGER.debug(
                'Vulnerability ignored: QID %s %s ''- Category: '
                '%s - Severity %d',
                vulnerability_dictionary[vulnerability]['qid'],
                vulnerability_dictionary[vulnerability]['title'],
                vulnerability_dictionary[vulnerability]['category'],
                vulnerability_dictionary[vulnerability]['severity']
                )

    return passed_vulnerabilities_counter


def get_quart_issue_list(jira_object, config):
    """
    Find all the JIRA VUMA issues created by Quart. If a custom field
    has been configured
    :param jira_object: jira session object
    :param config: confiture object that contains the quart configuration.
    :return: list of jira issues
    """
    jql_query = JQL_QUERY.format(
        config.subsection('jira').get('key'),
        config.subsection('jira').get('user')
    )
    temp_list = jira_object.search_issues(jql_query, maxResults=1000000)
    # If custom field configured: eliminate all issues that don't
    # have a custom field.
    if config.subsection('jira').get('custom_field'):
        result = []

        for issue in temp_list:
            if getattr(issue.fields, 'customfield_%s'%str(
                    config.subsection('jira').get('custom_field'))):
                result.append(issue)

        return result

    else:
        return temp_list


def verify_hostname(vulnerability):
    """
    Clears unresolved hostnames.
    :param vulnerability: vulnerability dictionary
    :param config: confiture object that contains the quart configuration.
    """
    LOGGER.debug(
        'Verifying hostnames for QID %s %s',
        vulnerability['qid'],
        vulnerability['title']
    )
    LOGGER.debug(
        'Hosts: %s',
        str(vulnerability['hosts'])
    )

    for host in vulnerability['hosts']:
        if host['name'] == 'No registered hostname':
            host['name'] = ''
            LOGGER.debug(
                'Cleared hostname for host %s',
                host['ip']
            )


def create_vulnerability_issue(jira_object, vulnerability, config):
    """
    Create a jira VUMA issue associated from a vulnerability dictionary
    :param jira_object: jira session object
    :param vulnerability: vulnerability dictionary
    :param config: confiture object that contains the quart configuration.
    :return: jira issue created
    """
    # Determine issue priority according to Quart settings
    if vulnerability['severity'] >= \
            config.subsection('jira').get('critical_min_sev'):
        priority = 'Critical'
    elif vulnerability['severity'] >= \
            config.subsection('jira').get('major_min_sev'):
        priority = 'Major'
    else:
        priority = 'Minor'

    description = ISSUE_DESCRIPTION.format(
        vulnerability['title'],
        vulnerability['qid'],
        vulnerability['category'],
        vulnerability['severity'],
        create_host_string(vulnerability['hosts']),
        vulnerability['diagnosis'],
        vulnerability['consequence'],
        vulnerability['solution']
    )
    issue_dictionary = {
        'project': config.subsection('jira').get('key'),
        'priority': {'name': priority},
        'description': description,
        'issuetype': {'name': 'Vulnerability'}
    }
    # If due_date configuration is enabled:
    if config.subsection('jira').get('due_date'):

        if priority == 'Critical':
            name = 'critical_eta'

        elif priority == 'Major':
            name = 'major_eta'

        else:
            name = 'low_eta'

        due_date = str(
            datetime.date.today() +
            datetime.timedelta(days=config.subsection('jira').get(name))
        )
        issue_dictionary['duedate'] = due_date

    # If a custom field is configured:
    if config.subsection('jira').get('custom_field'):
        issue_dictionary['summary'] = 'Quart: ' + vulnerability['title']
        issue_dictionary[
            'customfield_' + str(
                config.subsection('jira').get('custom_field'))] \
            = int(vulnerability['qid'])

    else:
        issue_dictionary['summary'] = \
            'Quart: Vulnerability ' + str(vulnerability['qid']) \
            + ' - ' + vulnerability['title']

    return jira_object.create_issue(fields=issue_dictionary)


def create_host_string(hosts):
    """
    Creates a string with a pleasant style to display ip address/hostnames
    in the Jira issue description=.
    :param hosts: a list of dictionaries
    :return: string
    """
    result = ''

    for host in hosts:
        result = result + ' | ' + host['ip']
        if host['name']:
            result = result + '(' + host['name'] + ')'

    return result


def get_vulnerability_issue_list(issue_list, vulnerability_qid, config):
    """
    Gets all the VUMA issues created by Quart for the vulnerability associated
    to the given QID.
    :param issue_list: list of all jira VUMA issues created by Quart
    :param vulnerability_qid: string of the qid
    :param config: confiture object that contains the quart configuration.
    :return: list of jira issues
    """
    result = []
    # Isolating issues for the given QID when a custom field is configured.
    if config.subsection('jira').get('custom_field'):

        for issue in issue_list:
            if int(vulnerability_qid) == \
                    getattr(issue.fields, 'customfield_%s'%str(
                        config.subsection('jira').get('custom_field'))):
                result.append(issue)

    # Isolating issues for a given QID when no custom field is configured.
    else:

        for issue in issue_list:
            temporary = re.search(r'\d+', str(issue.fields.summary))
            if temporary != None and str(int(temporary.group())) == \
                    vulnerability_qid:
                result.append(issue)

    return result


def update_jira_issues(jira_object, issue_list, vulnerability, config):
    """
    Function used when jira VUMA issues for this vulnerability have already
    been created by Quart. If a issue for that vulnerability is opened:update
    it. Otherwise, creates a new one and links all previous issues for that
    vulnerability.
    :param jira_object: jira session object
    :param issue_list: list of jira issues
    :param vulnerability: vulnerability dictionary
    :param config: confiture object that contains the quart configuration.
    """
    # Find the open issue for the issue
    open_issue = find_the_open_issue(issue_list)
    if open_issue != None:
        # Update open issue
        description = ISSUE_DESCRIPTION.format(
            vulnerability['title'],
            vulnerability['qid'],
            vulnerability['category'],
            vulnerability['severity'],
            create_host_string(vulnerability['hosts']),
            vulnerability['diagnosis'],
            vulnerability['consequence'],
            vulnerability['solution']
        )
        open_issue.update(description=description)
        LOGGER.info(
            'Updated issue: %s for QID %s - %s',
            str(open_issue),
            vulnerability['qid'],
            vulnerability['title'],
        )
    # No open issue: create a new issue and link older ones
    else:
        new_issue = \
            create_vulnerability_issue(jira_object, vulnerability, config)
        create_issue_links(jira_object, new_issue, issue_list)
        LOGGER.info(
            'Created new issue %s for QID %s %s',
            str(new_issue),
            vulnerability['qid'],
            vulnerability['title']
        )
        LOGGER.info(
            'Linked the follwing issues to the new issue: %s',
            str(issue_list)
        )


def find_the_open_issue(issue_list):
    """
    Finds a issue from the list that is opened (i.e. not 'Done' or
    'Canceled').
    :param issue_list: list of jira issues
    :return: jira issue
    """

    for issue in issue_list:
        open_issue_status = [
            'Awaiting Validation',
            'Awaiting Fix',
            'More Info Requested',
            'In Progress'
        ]
        if str(issue.fields.status) in open_issue_status:
            return issue

    return None


def create_issue_links(jira_object, issue, issues_to_link):
    """
    Creates 'Duplicate' links between issues
    :param jira_object: jira session object
    :param issue: jira issue that duplicates other issues
    :param issues_to_link: list of jira issues that will be linked to 'issue'
    """

    for temporary_issue in issues_to_link:
        jira_object.\
            create_issue_link('Duplicate', issue, temporary_issue, None)


def is_issue_canceled(issue_list):
    """
    Looks if any of the jira issues passed have the 'Canceled' status
    :param issue_list: list of jira issues
    :return: True or False
    """

    for issue in issue_list:
        if str(issue.fields.status) == 'Canceled':
            return True

    return False


def vulnerability_filter(vulnerability, issue_list, config):
    """
    Compares filter values from the config and the vulnerability to
    assess whether a issue should be created for this vulnerability.
    :param vulnerability: dictionary of a vulnerability
    :param issue_list: list of JIRA issues for this vulnerability
    :param config: confiture object that contains the quart configuration.
    :return: True or False
    """
    LOGGER.debug(
        'Applying filter for vulnerability QID %s  %s - '
        'Category: %s - Severity: %d',
        vulnerability['qid'],
        vulnerability['title'],
        vulnerability['category'],
        vulnerability['severity']
    )

    if is_issue_canceled(issue_list):
        LOGGER.debug(
            'Vulnerability ignored: VUMA issue for vulnerability canceled.'
        )
        return False

    elif vulnerability['category'] == 'Information gathering':
        if not config.subsection('filter').get('info_gathering'):
            LOGGER.debug(
                'Vulnerability ignored: Filter values indicate no '
                'information gathering vulnerabilities.'
            )
            return False
        elif vulnerability['severity'] >= \
                config.subsection('filter').get('min_info_severity'):
            LOGGER.debug(
                'Vulnerability passed: Filter values allow information '
                'gathering vulnerabilities.'
            )
            return True
        else:
            LOGGER.debug(
                'Vulnerability ignored: Vulnerability severity lower than '
                '<min_information_severity> filter value.'
            )
            return False

    elif config.subsection('filter').get('min_severity') <= \
            vulnerability['severity']:
        LOGGER.debug(
            'Vulnerability passed: vulnerability severity higher '
            'than <min_severity> filter value.'
        )
        return True

    elif config.subsection('filter').get('min_severity') > \
            vulnerability['severity']:
        LOGGER.debug(
            'Vulnerability ignored: vulnerability severity lower '
            'than <min_severity> filter value.'
        )
        return False

    else:
        LOGGER.warning(
            'Vulnerability did not fit in any filter scenarios'
        )
        return False
