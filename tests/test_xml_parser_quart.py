import pytest

from quart.xml_parser_quart import fusion_vulnerability_dictionaries

EXPECTED_1 = \
    {u'1': {'category': u'Category 1',
        'consequence': u'Consequence 1',
        'diagnosis': u'Diagnosis 1',
        'hosts': [{'ip': u'1.1.1.1', 'name': 'host1'},
                         {'ip': u'2.2.2.2', 'name': 'host2'}],
        'qid': u'1',
        'severity': 5,
        'solution': u'Solution 1',
        'title': u'Vulnerability Title 1'},
    u'2': {'category': u'Category 2',
        'consequence': u'Consequence 2',
        'diagnosis': u'Diagnosis 2',
        'hosts': [{'ip': u'2.2.2.2', 'name': 'host2'}],
        'qid': u'2',
        'severity': 4,
        'solution': u'Solution 2',
        'title': u'Vulnerability Title 2'}}

EXPECTED_2 = \
    {u'2': {'category': u'Category 2',
        'consequence': u'Consequence 2',
        'diagnosis': u'Diagnosis 2',
        'hosts': [{'ip': u'3.3.3.3', 'name': 'host3'}],
        'qid': u'2',
        'severity': 4,
        'solution': u'Solution 2',
        'title': u'Vulnerability Title 2'},
    u'3': {'category': u'Category 3',
        'consequence': u'Consequence 3',
        'diagnosis': u'Diagnosis 3',
        'hosts': [{'ip': u'4.4.4.4', 'name': 'host4'}],
        'qid': u'3',
        'severity': 3,
        'solution': u'Solution 3',
        'title': u'Vulnerability Title 3'}}

EXPECTED_1_2= \
    {u'1': {'category': u'Category 1',
        'consequence': u'Consequence 1',
        'diagnosis': u'Diagnosis 1',
        'hosts': [{'ip': u'1.1.1.1', 'name': 'host1'},
                         {'ip': u'2.2.2.2', 'name': 'host2'}],
        'qid': u'1',
        'severity': 5,
        'solution': u'Solution 1',
        'title': u'Vulnerability Title 1'},
    u'2': {'category': u'Category 2',
        'consequence': u'Consequence 2',
        'diagnosis': u'Diagnosis 2',
        'hosts': [{'ip': u'2.2.2.2', 'name': 'host2'},
                         {'ip': u'3.3.3.3', 'name': 'host3'}],
        'qid': u'2',
        'severity': 4,
        'solution': u'Solution 2',
        'title': u'Vulnerability Title 2'},
    u'3': {'category': u'Category 3',
        'consequence': u'Consequence 3',
        'diagnosis': u'Diagnosis 3',
        'hosts': [{'ip': u'4.4.4.4', 'name': 'host4'}],
        'qid': u'3',
        'severity': 3,
        'solution': u'Solution 3',
        'title': u'Vulnerability Title 3'}}


@pytest.mark.parametrize('dictionary_1, dictionary_2, fusion_dictionary', (
        ({}, {}, {}),
        ({}, EXPECTED_1, EXPECTED_1),
        (EXPECTED_2, {}, EXPECTED_2),
        (EXPECTED_1, EXPECTED_1, EXPECTED_1),
        (EXPECTED_1, EXPECTED_2, EXPECTED_1_2),
))

def test_fusion_vulnerability_dictionaries(dictionary_1, dictionary_2,
                                           fusion_dictionary):
    assert fusion_vulnerability_dictionaries(dictionary_1, dictionary_2) ==\
           fusion_dictionary