#!/usr/bin/env python3

import pytest

# importing testable functions
from replace_variables import parse_args
from replace_variables import make_list
from replace_variables import get_variables
from replace_variables import replace_variable_values

# input/output methods are not tested
#     display(message, verbose=False, exit=0):
#     read_file(filename):
#     write_file(filename, content, overwrite=False):
#     output_audit(content, output_file=[], overwrite=False):


def test_parse_args_with_no_parameters(capsys):
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parse_args([])
    assert pytest_wrapped_e.type == SystemExit
    (out, err) = capsys.readouterr()
    assert 'the following arguments are required' in err


def test_parse_args_defaults():
    args = parse_args(['test.audit'])
    assert args.timestamp == False
    assert args.verbose == False
    assert args.overwrite == False
    assert args.filename == ''
    assert args.audit == 'test.audit'


def test_parse_args_all_values():
    args = parse_args(['-t', '-v', '-o', '-f', 'output.audit', 'test.audit'])
    assert args.timestamp == True
    assert args.verbose == True
    assert args.overwrite == True
    assert args.filename == 'output.audit'
    assert args.audit == 'test.audit'


def test_make_list():
    assert make_list() == []
    assert make_list('abc') == ['abc']
    assert make_list(['abc']) == ['abc']
    assert make_list(['abc', 'def']) == ['abc', 'def']
    assert make_list({'abc': 'def'}) == [{'abc': 'def'}]


def test_get_variables_no_parameters():
    assert get_variables() == {}


def test_get_variables_no_content():
    assert get_variables('') == {}


def test_get_variables_no_variables_in_content():
    content = ('#<variables>\n'
               '#</variables>')
    assert get_variables(content) == {}


def test_get_variables_bad_variables_in_content(capsys):
    content = ('#<variables>\n'
               '#  <variable>\n'
               '#    <name>VAR_ONE</name>\n'
               '#    <value>Value One</value>\n'
               '#  </variable>\n'
               '#</variables>')
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        get_variables(content)
    assert pytest_wrapped_e.type == SystemExit
    (out, err) = capsys.readouterr()
    assert 'ERROR: Invalid variable' in err


def test_get_variables_single_variable():
    content = ('#<variables>\n'
               '#  <variable>\n'
               '#    <name>VAR_ONE</name>\n'
               '#    <default>Value One</default>\n'
               '#  </variable>\n'
               '#</variables>')
    assert get_variables(content) == { 'VAR_ONE': 'Value One' }


def test_get_variables_multiple_variables():
    content = ('#<variables>\n'
               '#  <variable>\n'
               '#    <name>VAR_ONE</name>\n'
               '#    <default>Value One</default>\n'
               '#  </variable>\n'
               '#  <variable>\n'
               '#    <name>VAR_TWO</name>\n'
               '#    <default>Value Two</default>\n'
               '#  </variable>\n'
               '#  <variable>\n'
               '#    <name>VAR_THREE</name>\n'
               '#    <default>Value Three</default>\n'
               '#  </variable>\n'
               '#</variables>')
    assert get_variables(content) == {
        'VAR_ONE': 'Value One',
        'VAR_TWO': 'Value Two',
        'VAR_THREE': 'Value Three'
    }


def test_replace_variable_values_no_content_or_values():
    assert replace_variable_values('', {}) == ''


def test_replace_variable_values_no_content():
    test_values = { 'VAR_ONE': 'Value One' }
    assert replace_variable_values('', test_values) == ''


def test_replace_variable_values_no_values():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '  info : "Test @VAR_ONE@ variable"\n'
                    '</custom_item>\n'
                    '</check_type>')
    assert replace_variable_values(test_content, {}) == test_content


def test_replace_variable_values_simple_content_and_values():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one"\n'
                    '  info : "Test @VAR_ONE@ variable"\n'
                    '</custom_item>\n'
                    '</check_type>')
    test_values = { 'VAR_ONE': 'Value One' }
    expected = test_content.replace('@VAR_ONE@', 'Value One')
    assert replace_variable_values(test_content, test_values) == expected


def test_replace_variable_values_multiple_values():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one and two"\n'
                    '  info : "Test @VAR_ONE@ variable"\n'
                    '  solution : "Test @VAR_TWO@ variable"\n'
                    '</custom_item>\n'
                    '</check_type>')
    test_values = { 'VAR_ONE': 'Value One', 'VAR_TWO': 'Value Two' }
    prepped = test_content.replace('@VAR_ONE@', 'Value One')
    expected = prepped.replace('@VAR_TWO@', 'Value Two')
    assert replace_variable_values(test_content, test_values) == expected


def test_replace_variable_values_multiple_values_in_same_line():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one and two"\n'
                    '  info : "Test @VAR_ONE@ and @VAR_TWO@ variable"\n'
                    '</custom_item>\n'
                    '</check_type>')
    test_values = { 'VAR_ONE': 'Value One', 'VAR_TWO': 'Value Two' }
    prepped = test_content.replace('@VAR_ONE@', 'Value One')
    expected = prepped.replace('@VAR_TWO@', 'Value Two')
    assert replace_variable_values(test_content, test_values) == expected


def test_replace_variable_values_prior_replaced_value():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one and two"\n'
                    '# Note: Variable @VAR_ONE@ replaced with "Other One" in '
                    'field "info".\n'
                    '  info : "Test Other One variable"\n'
                    '</custom_item>\n'
                    '</check_type>')
    test_values = { 'VAR_ONE': 'Value One' }
    expected = test_content.replace(' Other One ', ' Value One ')
    assert replace_variable_values(test_content, test_values) == expected


def test_replace_variable_values_prior_replaced_value_multiple():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one and two"\n'
                    '# Note: Variable @VAR_ONE@ replaced with "Other One" in '
                    'field "info".\n'
                    '  info : "Test Other One variable"\n'
                    '# Note: Variable @VAR_TWO@ replaced with "Other Two" in '
                    'field "solution".\n'
                    '  solution : "Test Other Two variable"\n'
                    '</custom_item>\n'
                    '</check_type>')
    test_values = { 'VAR_ONE': 'Value One', 'VAR_TWO': 'Value Two' }
    prepped = test_content.replace(' Other One ', ' Value One ')
    expected = prepped.replace(' Other Two ', ' Value Two ')
    assert replace_variable_values(test_content, test_values) == expected


def test_replace_variable_values_prior_replaced_value_multilple_on_line():
    test_content = ('<check_type:"Unix">\n'
                    '<custom_item>\n'
                    '  description: "Test value one and two"\n'
                    '# Note: Variable @VAR_ONE@ replaced with "Other One" in '
                    'field "info".\n'
                    '# Note: Variable @VAR_TWO@ replaced with "Other Two" in '
                    'field "info".\n'
                    '  info : "Test Other One and Other Two variable"\n'
                    '</custom_item>\n'
                    '</check_type>')
    test_values = { 'VAR_ONE': 'Value One', 'VAR_TWO': 'Value Two' }
    prepped = test_content.replace(' Other One ', ' Value One ')
    expected = prepped.replace(' Other Two ', ' Value Two ')
    assert replace_variable_values(test_content, test_values) == expected


if __name__ == '__main__':
    import pytest
    pytest.main(['-v', '.'])
