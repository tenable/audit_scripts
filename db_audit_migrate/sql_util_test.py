#!/usr/bin/env python3

import sql_util

def test_parse_types():
    assert sql_util.parse_types("POLICY_INTEGER") == ["INTEGER"]
    assert sql_util.parse_types("POLICY_INTEGER, POLICY_INTEGER") == ["INTEGER", "INTEGER"]
    assert sql_util.parse_types("POLICY_INTEGER, POLICY_VARCHAR") == ["INTEGER", "STRING"]
    assert sql_util.parse_types("POLICY_INTEGER, POLICY_VARCHAR, POLICY_INTEGER") == ["INTEGER", "STRING", "INTEGER"]
    assert sql_util.parse_types("POLICY_INTEGER,POLICY_VARCHAR,POLICY_INTEGER") == ["INTEGER", "STRING", "INTEGER"]
    assert sql_util.parse_types("POLICY_INTEGER,POLICY_VARCHAR,POLICY_VARCHAR") == ["INTEGER", "STRING", "STRING"]
    assert sql_util.parse_types("POLICY_VARCHAR") == ["STRING"]
    assert sql_util.parse_types("POLICY_VARCHAR, POLICY_INTEGER") == ["STRING", "INTEGER"]
    assert sql_util.parse_types("POLICY_VARCHAR, POLICY_INTEGER, POLICY_INTEGER") == ["STRING", "INTEGER", "INTEGER"]
    assert sql_util.parse_types("POLICY_VARCHAR, POLICY_VARCHAR") == ["STRING", "STRING"]
    assert sql_util.parse_types("POLICY_VARCHAR, POLICY_VARCHAR, POLICY_INTEGER") == ["STRING", "STRING", "INTEGER"]
    assert sql_util.parse_types("POLICY_VARCHAR,POLICY_INTEGER") == ["STRING", "INTEGER"]
    assert sql_util.parse_types("POLICY_VARCHAR,POLICY_INTEGER,POLICY_INTEGER") == ["STRING", "INTEGER", "INTEGER"]
    assert sql_util.parse_types("POLICY_VARCHAR,POLICY_INTEGER,POLICY_VARCHAR") == ["STRING", "INTEGER", "STRING"]
    assert sql_util.parse_types("POLICY_VARCHAR,POLICY_VARCHAR") == ["STRING", "STRING"]
    assert sql_util.parse_types("POLICY_VARCHAR,POLICY_VARCHAR,POLICY_INTEGER") == ["STRING", "STRING", "INTEGER"]


def test_type_of():
    assert sql_util.type_of('""') == 'STRING'
    assert sql_util.type_of("''") == 'STRING'
    assert sql_util.type_of('"ABC"') == 'STRING'
    assert sql_util.type_of('"DEF ZYX"') == 'STRING'
    assert sql_util.type_of('"@DEF ZYX@"') == 'STRING'
    assert sql_util.type_of('"DEF \\"ZYX\\""') == 'STRING'
    assert sql_util.type_of('0') == 'INTEGER'
    assert sql_util.type_of('10') == 'INTEGER'
    assert sql_util.type_of('908') == 'INTEGER'
    assert sql_util.type_of('regex:"ABC"') == 'REGEX'
    assert sql_util.type_of('regex: "DEF \\"ZYX\\""') == 'REGEX'
    assert sql_util.type_of("regex: 'DEF ZYX'") == 'REGEX'
    assert sql_util.type_of('NULL') == 'NULL'
    assert sql_util.type_of('[1..5]') == 'RANGE'
    assert sql_util.type_of('[1..MAX]') == 'RANGE'
    assert sql_util.type_of('9.08') == 'UNKNOWN'
    assert sql_util.type_of('null') == 'UNKNOWN'


def test_parse_expect():
    assert sql_util.parse_expect("\"\"") == [('STRING', '""')]
    assert sql_util.parse_expect("\"\", \"\"") == [('STRING', '""'), ('STRING', '""')]
    assert sql_util.parse_expect("\"\", \"35 or less\"") == [('STRING', '""'), ('STRING', '"35 or less"')]
    assert sql_util.parse_expect("\"ABC DEF GHI\"") == [('STRING', '"ABC DEF GHI"')]
    assert sql_util.parse_expect("\".+\",@MAX_FILES@") == [('STRING', '".+"'), ('INTEGER', '@MAX_FILES@')]
    assert sql_util.parse_expect("\"0\"") == [('STRING', '"0"')]
    assert sql_util.parse_expect("\"0\", regex:\"Last Password.*\"") == [('STRING', '"0"'), ('REGEX', 'regex:"Last Password.*"')]
    assert sql_util.parse_expect("\"1\"") == [('STRING', '"1"')]
    assert sql_util.parse_expect("\"1\", \"0\"") == [('STRING', '"1"'), ('STRING', '"0"')]
    assert sql_util.parse_expect("\"@ADMIN_USER@\", regex:\".+\"") == [('STRING', '"@ADMIN_USER@"'), ('REGEX', 'regex:".+"')]
    assert sql_util.parse_expect("\"@JOB_QUEUE_PROC@\"") == [('STRING', '"@JOB_QUEUE_PROC@"')]
    assert sql_util.parse_expect("\"@SA_ACCOUNT@\", 1") == [('STRING', '"@SA_ACCOUNT@"'), ('INTEGER', '1')]
    assert sql_util.parse_expect("\"ALERT\" || \"LOG\"") == [('COMPLEX', [('STRING', '"ALERT"'), ('STRING', '"LOG"')])]
    assert sql_util.parse_expect("\"AES_128\"||\"AES_192\"||\"AES_256\"||\"Triple_DES\"") == [('COMPLEX', [('STRING', '"AES_128"'), ('STRING', '"AES_192"'), ('STRING', '"AES_256"'), ('STRING', '"Triple_DES"')])]
    assert sql_util.parse_expect("\"EXCLUSIVE\" || \"NONE\"") == [('COMPLEX', [('STRING', '"EXCLUSIVE"'), ('STRING', '"NONE"')])]
    assert sql_util.parse_expect("0") == [('INTEGER', '0')]
    assert sql_util.parse_expect("102") == [('INTEGER', '102')]
    assert sql_util.parse_expect("@ABC@") == [('INTEGER', '@ABC@')]
    assert sql_util.parse_expect("4 || 6") == [('COMPLEX', [('INTEGER', '4'), ('INTEGER', '6')])]
    assert sql_util.parse_expect("4 || 6, \"ON\"") == [('COMPLEX', [('INTEGER', '4'), ('INTEGER', '6')]), ('STRING', '"ON"')]
    assert sql_util.parse_expect("NULL") == [('NULL', 'NULL')]
    assert sql_util.parse_expect("NULL, NULL") == [('NULL', 'NULL'), ('NULL', 'NULL')]
    assert sql_util.parse_expect("\"ManualReviewRequired\", NULL") == [('STRING', '"ManualReviewRequired"'), ('NULL', 'NULL')]
    assert sql_util.parse_expect("NULL || \"FALSE\"") == [('COMPLEX', [('NULL', 'NULL'), ('STRING', '"FALSE"')])]
    assert sql_util.parse_expect("NULL || regex: \"[Ff][Aa][Ll][Ss][Ee]\"") == [('COMPLEX', [('NULL', 'NULL'), ('REGEX', 'regex:"[Ff][Aa][Ll][Ss][Ee]"')])]
    assert sql_util.parse_expect("[1..100]") == [('RANGE', '[1..100]')]
    assert sql_util.parse_expect("[1..3]") == [('RANGE', '[1..3]')]
    assert sql_util.parse_expect("[1..@PG_KEEPALIVES_COUNT@]") == [('RANGE', '[1..@PG_KEEPALIVES_COUNT@]')]
    assert sql_util.parse_expect("[4..MAX]") == [('RANGE', '[4..MAX]')]
    assert sql_util.parse_expect("[MIN..MAX]") == [('RANGE', '[MIN..MAX]')]
    assert sql_util.parse_expect("[12..429496729]") == [('RANGE', '[12..429496729]')]


def test_compute_type_and_expect_simple():
    assert sql_util.compute_type_and_expect(('NULL', 'NULL')) == ('NULL', 'NULL')
    assert sql_util.compute_type_and_expect(('STRING', '""')) == ('STRING', '""')
    assert sql_util.compute_type_and_expect(('STRING', '"@ADMIN_USER@"')) == ('STRING', '"@ADMIN_USER@"')
    assert sql_util.compute_type_and_expect(('INTEGER', '0')) == ('INTEGER', '0')
    assert sql_util.compute_type_and_expect(('INTEGER', '102')) == ('INTEGER', '102')
    assert sql_util.compute_type_and_expect(('INTEGER', '@ABC@')) == ('INTEGER', '@ABC@')
    assert sql_util.compute_type_and_expect(('REGEX', 'regex:"@ABC@"')) == ('REGEX', '"@ABC@"')


def test_compute_type_and_expect_range():
    assert sql_util.compute_type_and_expect(('RANGE', '[1..100]')) == ('INTEGER', '[1..100]')
    assert sql_util.compute_type_and_expect(('RANGE', '[1..3]')) == ('INTEGER', '[1..3]')
    assert sql_util.compute_type_and_expect(('RANGE', '[1..@PG_KEEPALIVES_COUNT@]')) == ('INTEGER', '[1..@PG_KEEPALIVES_COUNT@]')
    assert sql_util.compute_type_and_expect(('RANGE', '[4..MAX]')) == ('INTEGER', '[4..MAX]')
    assert sql_util.compute_type_and_expect(('RANGE', '[MIN..MAX]')) == ('INTEGER', '[MIN..MAX]')
    assert sql_util.compute_type_and_expect(('RANGE', '[12..429496729]')) == ('INTEGER', '[12..429496729]')


def test_compute_type_and_expect_complex():
    assert sql_util.compute_type_and_expect(('COMPLEX', [('STRING', '"ALERT"'), ('STRING', '"LOG"')])) == ('REGEX', '"^(ALERT|LOG)$"')
    assert sql_util.compute_type_and_expect(('COMPLEX', [('STRING', '"AES_128"'), ('STRING', '"AES_192"'), ('STRING', '"AES_256"'), ('STRING', '"Triple_DES"')])) == ('REGEX', '"^(AES_128|AES_192|AES_256|Triple_DES)$"')
    assert sql_util.compute_type_and_expect(('COMPLEX', [('STRING', '"EXCLUSIVE"'), ('STRING', '"NONE"')])) == ('REGEX', '"^(EXCLUSIVE|NONE)$"')
    assert sql_util.compute_type_and_expect(('COMPLEX', [('REGEX', 'regex:"TRUE"'), ('REGEX', 'regex:"FALSE"')])) == ('REGEX', '"^(TRUE|FALSE)$"')
    assert sql_util.compute_type_and_expect(('COMPLEX', [('INTEGER', '4'), ('INTEGER', '6')])) == ('REGEX', '"^(4|6)$"')
    assert sql_util.compute_type_and_expect(('COMPLEX', [('INTEGER', '4'), ('INTEGER', '6'), ('STRING', '"ON"')])) == ('REGEX', '"^(4|6|ON)$"')
    assert sql_util.compute_type_and_expect(('COMPLEX', [('INTEGER', '1'), ('NULL', 'NULL')])) == ('INTEGER_OR_NULL', '1')
    assert sql_util.compute_type_and_expect(('COMPLEX', [('NULL', 'NULL'), ('STRING', '"FALSE"')])) == ('STRING_OR_NULL', '"FALSE"')
    assert sql_util.compute_type_and_expect(('COMPLEX', [('NULL', 'NULL'), ('REGEX', 'regex:"[Ff][Aa][Ll][Ss][Ee]"')])) == ('REGEX_OR_NULL', '"[Ff][Aa][Ll][Ss][Ee]"')
