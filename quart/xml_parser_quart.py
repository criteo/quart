"""
This module deals with all things relating to parsing
Qualys XML vulnerability scans reports, and creating
a dictionary of vulnerability dictionaries.
"""


def find_child_nodes_by_name(node_list, tag_name):
    """
    Returns a dom node from a dom NodeList that has a given tagName.
    :param node_list: NodeList dom object.
    :param tag_name: string
    :return: dom node with a tagName equal to tag_name
    """
    return [node for node in node_list
            if hasattr(node, 'tagName') and node.tagName == tag_name]


def get_vulnerability_dictionary_from_xml(root):
    """
    Returns a vulnerability dictionary built from the XML root.
    :param root: DOM NodeList object XML root of the Qualys report
    :return: dictionary of vulnerabilities
    """
    vulnerability_dictionary = {}

    for ip_element in root.getElementsByTagName('IP'):
        parse_ip_element(ip_element, vulnerability_dictionary)

    return vulnerability_dictionary


def parse_ip_element(ip_element, vulnerability_dictionary):
    """
    Looks at every IP element to get the IP address value,
    get the infos/services/vulns nodes and calls other functions.
    :param ip_element: DOM Node object
    :param vulnerability_dictionary: dictionary of vulnerabilities
    """
    ip = str(ip_element.getAttribute('value'))
    name = str(ip_element.getAttribute('name'))
    infos_nodes = find_child_nodes_by_name(ip_element.childNodes, 'INFOS')
    services_nodes = find_child_nodes_by_name(ip_element.childNodes,
                                              'SERVICES')
    vulns_nodes = find_child_nodes_by_name(ip_element.childNodes, 'VULNS')

    parse_nodes(infos_nodes, ip, name, vulnerability_dictionary,
                'INFO')
    parse_nodes(services_nodes, ip, name, vulnerability_dictionary,
                'SERVICE')
    parse_nodes(vulns_nodes, ip, name, vulnerability_dictionary,
                'VULN')


def parse_nodes(nodes, ip, name, vulnerability_dictionary, name_tag):
    """
    Looks at each node in the node list, creates a CAT dom object list, and
    calls a function to parse them.
    :param nodes: List of DOM Node objects
    :param ip: string IP of current IP node value
    :param name: hostname associated to the IP
    :param vulnerability_dictionary: dictionary of vulnerabilities
    :param name_tag: string, used later to call a function
    """

    for node in nodes:
        cat_node_list = find_child_nodes_by_name(node.childNodes, 'CAT')
        parse_cat_nodes(cat_node_list, ip, name,
                        vulnerability_dictionary, name_tag)


def parse_cat_nodes(cat_nodes, ip, name,
                    vulnerability_dictionary, name_tag):
    """
    Looks at every CAT node, gets the attribute value, and gets the
    next level of nodes, which are the nodes described by "name_tag".
    :param cat_nodes: List of DOM Node objects.
    :param ip: string of current IP node value
    :param name: hostname associated to the IP
    :param vulnerability_dictionary: dictionary of vulnerabilities
    :param name_tag: string, used later to call a function
    """
    for cat_node in cat_nodes:
        category = str(cat_node.getAttribute('value'))
        data_nodes = find_child_nodes_by_name(cat_node.childNodes, name_tag)
        parse_data_nodes(data_nodes, ip, name,
                         category, vulnerability_dictionary)


def parse_data_nodes(data_nodes, ip, name,
                     category, vulnerability_dictionary):
    """
    Looks at all the nodes, gets the vulnerability QID. Looks whether
    a dictionary for this vulnerability has already been created in which case
    it adds the ip node value. Else gathers more data on the vulnerability.
    :param data_nodes: List of DOM Node object
    :param ip: string of the current IP node value
    :param name: hostname associated to the IP
    :param category: string, cat value of the current cat node
    :param vulnerability_dictionary: dictionaty of vulnerabilities
    """
    for data_node in data_nodes:
        qid = data_node.getAttribute('number')
        if qid not in vulnerability_dictionary:
            severity = int(data_node.getAttribute('severity'))
            gather_remaining_data(
                data_node.childNodes, ip, name, category,
                qid, severity, vulnerability_dictionary
            )
        else:
            vulnerability_dictionary[qid]['hosts'].append(
                {'ip': ip, 'name': name}
            )


def gather_remaining_data(data, ip, name, category, qid, severity,
                          vulnerability_dictionary):
    """
    Gather the remaining information. Creates a new vulnerability dictionary
    in the dictionary of vulnerabilities.
    :param data: List of DOM Node objects
    :param ip: string of the current IP node value
    :param name: hostname associated to the IP
    :param category: string of the value of the current cat node
    :param qid: integer, qid of the current vulnerability being looked at
    :param severity: int, severity of the current vulnerability
    :param vulnerability_dictionary: dictionary of vulnerabilities
    """
    title = parse_data_text(data, 'TITLE')
    diagnosis = parse_data_text(data, 'DIAGNOSIS')
    consequence = parse_data_text(data, 'CONSEQUENCE')
    solution = parse_data_text(data, 'SOLUTION')
    vulnerability_dictionary[qid] = create_vulnerability_dictionary(
        qid,
        title,
        ip,
        name,
        category,
        severity,
        solution,
        diagnosis,
        consequence,
    )


def parse_data_text(data, name_tag):
    """
    Looks for the information described by "name_tag". If the information is
    not there, returns "N/A".
    :param data: List of DOM Node objects.
    :param name_tag: String, type of information we are looking for
    :return: String
    """
    if len(find_child_nodes_by_name(data, name_tag)) == 1:
        return str(find_child_nodes_by_name(data,
                                            name_tag)[0].firstChild.nodeValue)
    else:
        return "N/A"


def create_vulnerability_dictionary(qid, title,
                                    ip, name, category, severity,
                                    solution, diagnosis, consequence):
    """
    Creates a vulnerability dictionary.
    :param qid: integer Qualys ID of the vulnerability.
    :param title: string, title of the vulnerability.
    :param ip: list of IP adresses (strings) affected by vulnerability.
    :param name: hostname associated to the IP
    :param category: string, category of vulnerability.
    :param severity: integer, severity level of the vulnerability.
    :param solution: string, how to fix the vulnerability.
    :param diagnosis: string, how the vulnerability was detected.
    :param consequence: string, consequences of the vulnerability.
    :return: vulnerability dictionary with the entered values.
    """
    return {
        'qid': qid,
        'title': title,
        'hosts': [{'ip': ip, 'name': name}],
        'category': category,
        'severity': severity,
        'solution': solution,
        'diagnosis': diagnosis,
        'consequence': consequence,
    }


def fusion_vulnerability_dictionaries(dictionary_1, dictionary_2):
    """
    Fusions data from two vulnerability dictionaries into one.
    :param dictionary_1: dictionary of vulnerabilities
    :param dictionary_2: dictionary of vulnerabilities
    :return: dictionary of vulnerabilities
    """

    for qid in dictionary_2:
        if qid in dictionary_1:

            for host in dictionary_2[qid]['hosts']:
                if host not in dictionary_1[qid]['hosts']:
                    dictionary_1[qid]['hosts'].append(host)

        else:
            dictionary_1[qid] = dictionary_2[qid]

    return dictionary_1
