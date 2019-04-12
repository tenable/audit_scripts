#!/usr/bin/env python3

import pytest

# importing testable functions
from create_baseline_audit import parse_args
from create_baseline_audit import make_list
from create_baseline_audit import create_filename
from create_baseline_audit import strip_quotes
from create_baseline_audit import get_values_from_nessus
from create_baseline_audit import apply_values_to_audit
from create_baseline_audit import get_plugin_from_contents
from create_baseline_audit import quote_and_escape_value
from create_baseline_audit import format_reference

# variables imported for testing only
from create_baseline_audit import show_time
from create_baseline_audit import show_verbose

# input/output methods are not tested
#     display(message, verbose=False, exit=0):
#     read_file(filename):
#     write_file(filename, content, overwrite=False):
#     output_audits(audits, overwrite, output_file):


test_items = [
    '<spam>',
    '<ReportItem port="0" svc_name="general" protocol="tcp" severity="3" pluginID="21156" pluginName="Windows Compliance Checks" pluginFamily="Policy Compliance">\n<agent>windows</agent>\n<compliance>true</compliance>\n<fname>compliance_check.nbin</fname>\n<plugin_modification_date>2018/06/21</plugin_modification_date>\n<plugin_name>Windows Compliance Checks</plugin_name>\n<plugin_publication_date>2007/11/21</plugin_publication_date>\n<plugin_type>local</plugin_type>\n<risk_factor>None</risk_factor>\n<script_version>$Revision: 1.305 $</script_version>\n<cm:compliance-check-name>Test value one</cm:compliance-check-name>\n<cm:compliance-actual-value>0</cm:compliance-actual-value>\n<description>&quot;Test value one&quot;: [FAILED]\n</description>\n<cm:compliance-audit-file>CIS_MS_Windows_7_L1_v3.0.1.var_replace.audit</cm:compliance-audit-file>\n<cm:compliance-check-id>993c788cf6b875e558ea4d65476dc71e</cm:compliance-check-id>\n<cm:compliance-policy-value>[24..4294967295]</cm:compliance-policy-value>\n<cm:compliance-info>\nAbridged compliance\ninformation here</cm:compliance-info>\n<cm:compliance-result>FAILED</cm:compliance-result>\n<cm:compliance-reference>800-171|3.5.8,800-53|IA-5</cm:compliance-reference>\n<cm:compliance-solution>Abridged compliance\nsolution here</cm:compliance-solution>\n<cm:compliance-see-also>https://benchmarks.cisecurity.org/tools2/windows/CIS_Microsoft_Windows_7_Workstation_Benchmark_v3.0.1.pdf</cm:compliance-see-also>\n</ReportItem>',
    '<ReportItem>\n<cm:compliance-check-name>Test value two</cm:compliance-check-name>\n<cm:compliance-result>FAILED</cm:compliance-result><cm:compliance-actual-value>0</cm:compliance-actual-value>\n</ReportItem>',
    '<ReportItem>\n<cm:compliance-check-name>Test value three</cm:compliance-check-name>\n<cm:compliance-result>PASSED</cm:compliance-result><cm:compliance-actual-value>This is\nmulti-line</cm:compliance-actual-value>\n</ReportItem>',
    '<ReportItem>\n<cm:compliance-check-name>Test value two for 2nd host</cm:compliance-check-name>\n<cm:compliance-result>WARNING</cm:compliance-result><cm:compliance-actual-value>1</cm:compliance-actual-value>\n</ReportItem>'
]


def generate_test_content(definition={}):
    global test_items

    content = ('<?xml version="1.0" ?><NessusClientData_v2><Policy>'
               '<policyName>Audit Cloud Infrastructure</policyName>'
               '<Preferences><ServerPreferences><preference><name>plugin_set'
               '</name><value>87413;84239;72426;</value></preference>'
               '<preference><name>TARGET</name><value>127.0.0.1</value>'
               '</preference></ServerPreferences></Preferences></Policy>'
               '<Report name="Test Baseline Scan" '
               'xmlns:cm="http://www.nessus.org/cm">')

    for host_id in definition:
        content += ('<ReportHost name="__HOST_ID__"><HostProperties>'
                    '<tag name="host-ip">__HOST_ID__</tag>'
                    '</HostProperties>').replace('__HOST_ID__', host_id)
        for test_id in definition[host_id]:
            content += test_items[test_id]

        content += '</ReportHost>'

    content += '</Report></NessusClientData_v2>'

    return content


def test_parse_args_with_no_parameters(capsys):
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parse_args([])
    assert pytest_wrapped_e.type == SystemExit
    (out, err) = capsys.readouterr()
    assert 'the following arguments are required' in err


def test_parse_args_defaults():
    args = parse_args(['test.audit', 'test.nessus'])
    assert args.timestamp == False
    assert args.verbose == False
    assert args.overwrite == False
    assert args.filename == ''
    assert args.audit == 'test.audit'
    assert args.nessus == 'test.nessus'


def test_parse_args_all_values():
    from create_baseline_audit import show_time
    from create_baseline_audit import show_verbose
    args = parse_args(['-t', '-v', '-o', '-f', 'output.audit',
                       'test.audit', 'test.nessus'])
    assert args.timestamp == True
    assert args.verbose == True
    assert args.overwrite == True
    assert args.filename == 'output.audit'
    assert args.audit == 'test.audit'
    assert args.nessus == 'test.nessus'


def test_make_list():
    assert make_list() == []
    assert make_list('abc') == ['abc']
    assert make_list(['abc']) == ['abc']
    assert make_list(['abc', 'def']) == ['abc', 'def']
    assert make_list({'abc': 'def'}) == [{'abc': 'def'}]


def test_create_filename():
    tests = [
        ('abc.audit', '123.456.789.1', 'abc.123.456.789.1.audit'),
        ('abc.def.audit', '123.456.789.1', 'abc.def.123.456.789.1.audit'),
        ('abc.def.audit', 1, 'abc.def.1.audit'),
        ('abc_def.txt', 1, 'abc_def.1.txt')
    ]
    for (filename, host, expected) in tests:
        assert create_filename(filename, host) == expected


def test_strip_quotes():
    tests = [
        ('abc', 'abc'),
        ('"abc"', 'abc'),
        ('abc"', 'abc"'),
        ('"abc', '"abc'),
        ("'abc'", 'abc'),
        ("abc'", "abc'"),
        ("'abc", "'abc"),
        (1, 1),
        ('1', '1'),
        ('"1"', '1'),
        ({'abc': 'def'}, {'abc': 'def'}),
        (['"abc"', "'def'"], ['abc', 'def']),
        (['abc"', "'def", '"ghi"'], ['abc"', "'def", 'ghi'])
    ]
    for value, expected in tests:
        assert strip_quotes(value) == expected


def test_get_values_from_nessus_invalid_xml(capsys):
    values = generate_test_content({'192.168.0.10': (0,)})
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        get_values_from_nessus(values)
    assert pytest_wrapped_e.type == SystemExit
    (out, err) = capsys.readouterr()
    assert 'ERROR: parsing nessus file' in err


def test_get_values_from_nessus_no_report_items():
    values = generate_test_content({'192.168.0.10': ()})
    assert get_values_from_nessus(values) == {'192.168.0.10': {}}


def test_get_values_from_nessus_single_item():
    values = generate_test_content({'192.168.0.10': (1,)})
    assert get_values_from_nessus(values) == {
        '192.168.0.10': {
            'Test value one': ('0', 'FAILED')
        }
    }


def test_get_values_from_nessus_bare_bones_report_item():
    values = generate_test_content({'192.168.0.10': (2,)})
    assert get_values_from_nessus(values) == {
        '192.168.0.10': {
            'Test value two': ('0', 'FAILED')
        }
    }


def test_get_values_from_nessus_multiple_values():
    values = generate_test_content({'192.168.0.10': (1, 2)})
    assert get_values_from_nessus(values) == {
        '192.168.0.10': {
            'Test value one': ('0', 'FAILED'),
            'Test value two': ('0', 'FAILED')
        }
    }


def test_get_values_from_nessus_multiple_hosts():
    values = generate_test_content({
        '192.168.0.10': (2,),
        '192.168.0.11': (4,)
    })
    assert get_values_from_nessus(values) == {
        '192.168.0.10': {
            'Test value two': ('0', 'FAILED')
        },
        '192.168.0.11': {
            'Test value two for 2nd host': ('1', 'WARNING')
        }
    }


def test_get_values_from_nessus_value_with_newline():
    values = generate_test_content({'192.168.0.10': (3,)})
    assert get_values_from_nessus(values) == {
        '192.168.0.10': {
            'Test value three': ('This is\nmulti-line', 'PASSED')
        }
    }


def test_apply_values_to_audit_no_content_or_values():
    assert apply_values_to_audit('abc.audit', '', {}) == {}


def test_apply_values_to_audit_no_content():
    test_values = { '192.168.0.10': { 'Test value one': ('0', 'PASSED') }}
    expected = {'abc.192.168.0.10.audit': ''}
    assert apply_values_to_audit('abc.audit', '', test_values) == expected


def test_apply_values_to_audit_no_values():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '</custom_item>'
                    '</check_type>')
    actual = apply_values_to_audit('abc.audit', test_content, {})
    expected = {}
    assert actual == expected


def test_apply_values_to_audit_simple_content_and_values():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '</custom_item>\n'
                    '</check_type>')
    expected_content = ('<check_type:"Unix">\n'
                        '<custom_item>\n'
                        '  description: "Test value one"\n'
                        '  known_good : "0"\n'
                        '</custom_item>\n'
                        '</check_type>')
    test_values = { '192.168.0.10': { 'Test value one': ('0', 'PASSED') }}
    actual = apply_values_to_audit('abc.audit', test_content, test_values)
    expected = {'abc.192.168.0.10.audit': expected_content}
    assert actual == expected


def test_apply_values_to_audit_simple_content_and_values_with_ref():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '</custom_item>\n'
                    '</check_type>')
    expected_content = ('<check_type:"Unix">\n'
                        '<custom_item>\n'
                        '  description: "Test value one"\n'
                        '  reference : "ABC|compliant"\n'
                        '  known_good : "0"\n'
                        '</custom_item>\n'
                        '</check_type>')
    test_values = { '192.168.0.10': { 'Test value one': ('0', 'PASSED') }}
    actual = apply_values_to_audit('abc.audit', test_content, test_values, 'ABC')
    expected = {'abc.192.168.0.10.audit': expected_content}
    assert actual == expected


def test_apply_values_to_audit_simple_content_and_values_with_add_ref():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '  reference : "800-53|CM-7"\n'
                    '</custom_item>\n'
                    '</check_type>')
    expected_content = ('<check_type:"Unix">\n'
                        '<custom_item>\n'
                        '  description: "Test value one"\n'
                        '  reference : "800-53|CM-7,ABC|compliant"\n'
                        '  known_good : "0"\n'
                        '</custom_item>\n'
                        '</check_type>')
    test_values = { '192.168.0.10': { 'Test value one': ('0', 'PASSED') }}
    actual = apply_values_to_audit('abc.audit', test_content, test_values, 'ABC')
    expected = {'abc.192.168.0.10.audit': expected_content}
    assert actual == expected


def test_apply_values_to_audit_simple_content_and_values_with_replace_ref():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '  reference : "ABC|deviation,800-53|CM-7"\n'
                    '</custom_item>\n'
                    '</check_type>')
    expected_content = ('<check_type:"Unix">\n'
                        '<custom_item>\n'
                        '  description: "Test value one"\n'
                        '  reference : "ABC|compliant,800-53|CM-7"\n'
                        '  known_good : "0"\n'
                        '</custom_item>\n'
                        '</check_type>')
    test_values = { '192.168.0.10': { 'Test value one': ('0', 'PASSED') }}
    actual = apply_values_to_audit('abc.audit', test_content, test_values, 'ABC')
    expected = {'abc.192.168.0.10.audit': expected_content}
    assert actual == expected


def test_apply_values_to_audit_multiple_known_goods():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '  known_good : "0"\n'
                    '</custom_item>\n'
                    '</check_type>')
    expected_content = ('<check_type:"Unix">\n'
                        '<custom_item>\n'
                        '  description: "Test value one"\n'
                        '  known_good : "0"\n'
                        '  known_good : "1"\n'
                        '</custom_item>\n'
                        '</check_type>')
    test_values = { '192.168.0.10': { 'Test value one': ('1', 'PASSED') }}
    actual = apply_values_to_audit('abc.audit', test_content, test_values)
    expected = {'abc.192.168.0.10.audit': expected_content}
    assert actual == expected


def test_apply_values_to_audit_multiple_known_goods_with_ref():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '  known_good : "0"\n'
                    '</custom_item>\n'
                    '</check_type>')
    expected_content = ('<check_type:"Unix">\n'
                        '<custom_item>\n'
                        '  description: "Test value one"\n'
                        '  known_good : "0"\n'
                        '  reference : "ABC|deviation"\n'
                        '  known_good : "1"\n'
                        '</custom_item>\n'
                        '</check_type>')
    test_values = { '192.168.0.10': { 'Test value one': ('1', 'FAILED') }}
    actual = apply_values_to_audit('abc.audit', test_content, test_values, 'ABC')
    expected = {'abc.192.168.0.10.audit': expected_content}
    assert actual == expected


def test_apply_values_to_audit_multiple_hosts():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '</custom_item>\n'
                    '</check_type>')
    expected_content = ('<check_type:"Unix">\n'
                        '<custom_item>\n'
                        '  description: "Test value one"\n'
                        '  known_good : "__VAL__"\n'
                        '</custom_item>\n'
                        '</check_type>')
    test_values = {
        '192.168.0.10': { 'Test value one': ('0', 'PASSED') },
        '192.168.0.11': { 'Test value one': ('1', 'PASSED') }
    }
    actual = apply_values_to_audit('abc.audit', test_content, test_values)
    expected = {
        'abc.192.168.0.10.audit': expected_content.replace('__VAL__', '0'),
        'abc.192.168.0.11.audit': expected_content.replace('__VAL__', '1')
    }
    assert actual == expected


def test_apply_values_to_audit_multiple_hosts_with_ref():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '</custom_item>\n'
                    '</check_type>')
    expected_content = ('<check_type:"Unix">\n'
                        '<custom_item>\n'
                        '  description: "Test value one"\n'
                        '  reference : "ABC|compliant"\n'
                        '  known_good : "__VAL__"\n'
                        '</custom_item>\n'
                        '</check_type>')
    test_values = {
        '192.168.0.10': { 'Test value one': ('0', 'PASSED') },
        '192.168.0.11': { 'Test value one': ('1', 'PASSED') }
    }
    actual = apply_values_to_audit('abc.audit', test_content, test_values, 'ABC')
    expected = {
        'abc.192.168.0.10.audit': expected_content.replace('__VAL__', '0'),
        'abc.192.168.0.11.audit': expected_content.replace('__VAL__', '1')
    }
    assert actual == expected


def test_apply_values_to_audit_quoted_values():
    test_content = ('<check_type:"Cisco">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '</custom_item>\n'
                    '</check_type>')
    expected_content = ('<check_type:"Cisco">\n'
                        '<custom_item>\n'
                        '  description: "Test value one"\n'
                        '  known_good : __VAL__\n'
                        '</custom_item>\n'
                        '</check_type>')
    test_values = [
        [{ '192.168.0.10': { 'Test value one': ('ab"cd', 'PASSED') }}, '\'ab"cd\''],
        [{ '192.168.0.10': { 'Test value one': ("ab'cd", 'PASSED') }}, '"ab\'cd"'],
        [{ '192.168.0.10': { 'Test value one': ('abcd', 'PASSED') }}, '"abcd"'],
        [{ '192.168.0.10': { 'Test value one': ('a"bc\'"d', 'PASSED') }}, '"a\\"bc\'\\"d"']
    ]
    for (test_value, expected_value) in test_values:
        actual = apply_values_to_audit('abc.audit', test_content, test_value)
        test_expected = expected_content.replace('__VAL__', expected_value)
        expected = {'abc.192.168.0.10.audit': test_expected}
        assert actual == expected


def test_format_reference():
    assert format_reference('PASSED', 'a') == 'a|compliant'
    assert format_reference('WARNING', 'b') == 'b|review'
    assert format_reference('FAILED', 'c') == 'c|deviation'
    assert format_reference('SPAM', 'd') == 'd|review'


def test_get_plugin_from_contents():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '</custom_item>\n'
                    '</check_type>')

    assert get_plugin_from_contents(None) == 'Generic'
    assert get_plugin_from_contents('') == 'Generic'
    assert get_plugin_from_contents(test_content) == 'Unix'
    assert get_plugin_from_contents('\n < check_type : "Windows" version : "2">') == 'Windows'
    assert get_plugin_from_contents('<check_type	:	"Cisco">') == 'Cisco'


def test_quote_and_escape_value():
    assert quote_and_escape_value(None, None) == None
    assert quote_and_escape_value('', None) == '""'
    assert quote_and_escape_value('abc', None) == '"abc"'
    assert quote_and_escape_value("a'bc", None) == '"a\'bc"'
    assert quote_and_escape_value("a\"bc", None) == "'a\"bc'"
    assert quote_and_escape_value("a\"bc", 'Windows') == "'a\"bc'"
    assert quote_and_escape_value("a\"bc", 'Unix') == '"a\\"bc"'


if __name__ == '__main__':
    import pytest
    pytest.main(['-v', '.'])
