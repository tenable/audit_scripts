#!/usr/bin/env python3

import re

type_map = {
    'POLICY_INTEGER': 'INTEGER',
    'POLICY_VARCHAR': 'STRING'
}

integer_re = re.compile(r'^[0-9]+$')
range_re = re.compile(r'^\[(MIN|@[^ ]*@|[0-9]+)\.\.(MAX|@[^ ]*@|[0-9]+)\]$')
regex_re = re.compile(r'^regex *: *["\']')


def parse_types(target):
    types = [t.strip() for t in target.split(',')]

    return [type_map[t] for t in types]


def type_of(target):
    global integer_re, range_re, regex_re

    if target == 'NULL':
        return 'NULL'
    elif target == 'NO_ROWS_RETURNED':
        return 'STRING'
    elif len(target) > 1 and target[0] in '"\'' and target[0] == target[-1]:
        return 'STRING'
    elif len(target) > 1 and target[0] == '@' and target[0] == target[-1]:
        return 'INTEGER'      # variables outside of quotes are integers
    elif integer_re.search(target):
        return 'INTEGER'
    elif regex_re.search(target):
        return 'REGEX'
    elif range_re.search(target):
        return 'RANGE'
    else:
        return 'UNKNOWN'


def _parse_string(target, i, stop):
    e = target.index(stop, i + 1)
    while target[e - 1] in '\\':
        e = target.index(stop, e + 1)
    val = target[i:e + 1]
    return val, e


def parse_expect(target):
    result = []

    idx = 0 
    i = 0
    while i < len(target):
        val = None
        if target[i] in '"\'':
            val, i = _parse_string(target, i, target[i])
        elif target[i] in '[':
            val, i = _parse_string(target, i, ']')
        elif target[i] in '@':
            val, i = _parse_string(target, i, '@')
        elif target[i] in '1234567890':
            e = i
            while e + 1 < len(target) and target[e + 1] in '1234567890':
                e += 1
            val = target[i:e + 1]
            i = e
        elif target[i] in 'r' and target[i:i + 5] == 'regex':
            i = i + 5
            while target[i] not in '"\'': i += 1
            re_val, i = _parse_string(target, i, target[i])
            val = 'regex:{}'.format(re_val)
        elif target[i] in 'N' and target[i:i + 4] == 'NULL':
            val = 'NULL'
            i = i + 3
        elif target[i] in 'N' and target[i:i + 16] == 'NO_ROWS_RETURNED':
            val = 'NO_ROWS_RETURNED'
            i = i + 15
        elif target[i] in ' |':
            pass
        elif target[i] in ',':
            idx += 1
        else:
            raise Exception(target[i])

        if val is None:
            pass
        else:
            val_type = (type_of(val), val)
            if idx == len(result):
                result.append(val_type)
            else:
                if result[-1][0] == 'COMPLEX':
                    result[-1][1].append(val_type)
                else:
                    result[-1] = ('COMPLEX', [result[-1], val_type])
        i += 1

    return result


def compute_type_and_expect(target):
    val_type = target[0]
    val_expect = target[1]

    if val_type == 'RANGE':
        val_type = 'INTEGER'
    elif val_type == 'COMPLEX':
        # if range in list... can't support yet
        if 'RANGE' in [v[0] for v in val_expect[1]]:
            raise Exception('Unable to process complex range: {}'.format(val_type))
        # check if any NULL and update or_null
        or_null = ''
        for i in reversed(range(len(val_expect))):
            if val_expect[i][0] == 'NULL':
                or_null = '_OR_NULL'
                del val_expect[i]

        # if multiple values still exist, collapse to REGEX
        vals = [v[1].replace('regex:', '').strip('"\'') for v in val_expect]
        if len(vals) > 1:
            val_type = 'REGEX'
            val_expect = '"^({})$"'.format('|'.join(vals))
        else:
            val_type = val_expect[0][0]
            val_expect = val_expect[0][1].replace('regex:', '')

        val_type = '{}{}'.format(val_type, or_null)
    else:
        val_expect = val_expect.replace('regex:', '')

    # make sure value is double quoted
    if len(val_expect) >=2 and val_expect[0] == "'":
        val = val_expect[1:-1].replace('"', '\\"')
        val_expect = '"{}"'.format(val)

    return (val_type, val_expect)



