"""
This module deals with everything realted to the Qualys API.
- Login Qualys APIv2
- Obtain list of reports that fit the parameters
- Parse XML of report list, obtain scan references.
- Download the scans (using API v1)
- Logout of APIv2
"""
import datetime
import logging
import xml.dom.minidom

import requests
from requests.auth import HTTPBasicAuth


LOGGER = logging.getLogger(__name__)


def get_qualys_reports(config):
    """
    :return: List of XML vulnerability results
    """
    session = requests.session()
    session.headers.update({'X-Requested-With': 'Quart'})
    LOGGER.debug('Qualys API session login')
    login_answer = qualys_login(session, config)
    show_answer_detail(login_answer)
    LOGGER.debug('Download report list')
    report_list_answer = get_report_list(session, config)
    show_answer_detail(report_list_answer)
    reports_references_list = get_reports_references(
        report_list_answer.content, config)
    LOGGER.debug('Report references list: %s', str(reports_references_list))
    report_list = download_reports(reports_references_list)
    LOGGER.debug('Qualys API session logout')
    logout_answer = qualys_logout(session, config)
    show_answer_detail(logout_answer)
    session.close()
    return report_list


def show_answer_detail(answer):
    """
    Displays information about the requests object passed as arguement.
    :param answer: requests object
    """
    LOGGER.debug(answer)
    LOGGER.debug(answer.headers)
    LOGGER.debug(answer.content)


def qualys_login(session_object, config):
    """
    Logs in the Qualys API v2
    :param session_object: requests session object of the current session.
    :param config: confiture object that contains the quart configuration.
    :return: requests session oject, answer of the server.
    """
    payload = {
        'action': 'login',
        'username': config.subsection('qualys').get('user'),
        'password': config.subsection('qualys').get('password')
    }
    return session_object.post(
        'https://qualysapi.qualys.eu/api/2.0/fo/session/',
        data=payload)


def get_report_list(session_object, config):
    """
    Asks the Qualys API V2 for a list of scans.
    :param session_object: requests session object of the current session.
    :param config: confiture object that contains the quart configuration.
    :return: requests session oject, answer of the server.
    """
    today = datetime.date.today().strftime('%Y-%m-%dT00:00:00Z')
    yesterday = datetime.date.fromordinal(
        datetime.date.today().toordinal()-1).strftime('%Y-%m-%dT00:00:00Z')
    payload = {'action': 'list',
               'launched_after_datetime': yesterday,
               'launched_before_datetime': today,
               'state': 'Finished'
              }
    url = config.subsection('qualys').get('url') + '/api/2.0/fo/scan/'
    return session_object.post(url, data=payload)


def qualys_logout(session_object, config):
    """
    Logs out of the Qualys API v2
    :param session_object: requests session object of the current session.
    :param config: confiture object that contains the quart configuration.
    :return: requests session oject, answer of the server.
    """
    payload = {'action': 'logout'}
    url = config.subsection('qualys').get('url') + '/api/2.0/fo/session/'
    return session_object.post(url, data=payload)


def get_reports_references(report_list, config):
    """
    Goes through the report_list XML and locates the scan nodes.
    :param report_list: string of an XML.
    :param config: confiture object that contains the quart configuration.
    :return: returns a list of strings that are scan references.
    """
    root = xml.dom.minidom.parseString(report_list).documentElement
    response_nodes = find_child_nodes_by_name(root.childNodes, 'RESPONSE')
    if len(response_nodes) == 1:
        scan_list_node = find_child_nodes_by_name(response_nodes[0].childNodes,
                                                  'SCAN_LIST')
        if len(scan_list_node) == 1:
            scan_nodes = find_child_nodes_by_name(
                scan_list_node[0].childNodes,
                'SCAN'
            )
            return go_through_scan_nodes(scan_nodes, config)
    else:
        return []


def find_child_nodes_by_name(node_list, tag_name):
    """
    Returns a dom node from a dom NodeList that has a given tagName.
    :param node_list: NodeList dom object.
    :param tag_name: string
    :return: dom node with a tagName equal to tag_name
    """
    return [node for node in node_list
            if hasattr(node, 'tagName') and node.tagName == tag_name]


def go_through_scan_nodes(scan_nodes_list, config):
    """
    Finds the scan reference from a scan node in the scan
    has 'Used by Quart' in its title.
    :param scan_nodes_list: NodeList dom object.
    :param config: confiture object that contains the quart configuration.
    :return: returns a list of strings that are scan references.
    """
    result = []

    for scan_node in scan_nodes_list:
        title_node = find_child_nodes_by_name(scan_node.childNodes, 'TITLE')

        if len(title_node) == 1:

            # If scan title hook configured
            if config.subsection('qualys').get('scan_title_hook') and \
                config.subsection('qualys').get('scan_title_hook') in \
                str(title_node[0].firstChild.nodeValue):
                ref_node = \
                    find_child_nodes_by_name(scan_node.childNodes, 'REF')
                if len(ref_node) == 1:
                    result.append(str(ref_node[0].firstChild.nodeValue))

            # If no scan_title_hook configured
            elif not config.subsection('qualys').get('scan_title_hook'):
                ref_node = \
                    find_child_nodes_by_name(scan_node.childNodes, 'REF')
                if len(ref_node) == 1:
                    result.append(str(ref_node[0].firstChild.nodeValue))

    return result


def download_reports(scan_references):
    """
    Downloads all the scans corresponding to the references given
    using the API v1 of Qualys.
    :param scan_references: list of strings, scan references.
    :return: list of requests object, they are the server's answers and
    contain the scan XML results.
    """
    result = []

    for reference in scan_references:
        payload = {'ref': reference}
        LOGGER.info('Downloading results for scan %s', reference)
        result.append(requests.post(
            'https://qualysapi.qualys.eu/msp/scan_report.php?',
            auth=HTTPBasicAuth(config.subsection('qualys').get('user'), config.subsection('qualys').get('password')),
            params=payload
        ))

    return result
