#!/usr/bin/env python3

# Description : This script is a utility to convert audit files that were
#               written for the Database Compliance Check plugin and format
#               them to a new structure to support individual database
#               technology plugins.


import argparse
import datetime
import os
import re
import sys

import sql_util


show_verbose = False
show_time = False

check_type_re = re.compile('^\\s*<\\s*check_type\\s*:\\s*"([^"]+)".*>')
db_type_re = re.compile('^\\s*<\\s*check_type\\s*:\\s*"([^"]+)".*db_type\\s*:\\s*"([^"]+)".*>')
group_policy_re = re.compile('^\\s*</?\\s*group_policy\\s*(:\\s*"([^"]+)"\\s*)?>')
open_item_re = re.compile('^\\s*<\\s*custom_item\\s*>')
close_item_re = re.compile('^\\s*</\\s*custom_item\\s*>')
field_replace_re = re.compile('^(\\s*[^\\s:]+\\s*: *).*$')
sql_field_re = re.compile('^\\s*(sql_(request|types|expect))\\s*:\\s.*')
simple_quoted_field_re = re.compile('^\\s*([a-z0-9_-]+)\\s*:\\s*(["\'])[^\\2]*\\2\\s*$')
simple_unquoted_field_re = re.compile('^\\s*([a-z0-9_-]+)\\s*:\\s*[A-Za-z0-9_-]+\\s*$')
select_re = re.compile('(?i)^select\\s(.*?) from')


def parse_args(parameters):
    global show_time, show_verbose

    default_output = '.'

    parser = argparse.ArgumentParser(description=('Convert Database audits '
                                                  'to individual technology '
                                                  'database audits.'))

    parser.add_argument('-t', '--timestamp', action='store_true',
                        help='show timestamp on output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show verbose output')

    parser.add_argument('-o', '--output', nargs=1, default=default_output,
                        help='output directory for new audits')
    parser.add_argument('-r', '--replace', action='store_true',
                        help='overwrite existing files')

    parser.add_argument('audit', type=str, nargs='+',
                        help='audit file(s) to process')

    args = parser.parse_args(parameters)

    if args.timestamp:
        show_time = True
    if args.verbose:
        show_verbose = True

    if isinstance(args.output, list):
        if len(args.output) > 0:
            args.output = args.output[0]
        else:
            args.output = default_output

    return args


def make_list(target=None):
    if target is None:
        return []
    elif isinstance(target, list):
        return target
    else:
        return [target]


def display(message, verbose=False, exit=0):
    global show_time, show_verbose

    if show_time:
        now = datetime.datetime.now()
        timestamp = datetime.datetime.strftime(now, '%Y/%m/%d %H:%M:%S')
        message = '{} {}'.format(timestamp, message)

    out = sys.stdout
    if exit > 0:
        out = sys.stderr

    if verbose and show_verbose:
        out.write(message.rstrip() + '\n')
    elif not verbose:
        out.write(message.rstrip() + '\n')

    if exit > 0:
        sys.exit(exit)


def find_files(paths, pattern='.', partial=False):
    paths = make_list(paths)
    files = []
    pattern_re = re.compile(pattern, re.I)

    for item in paths:
        if os.path.isfile(item):
            files.append(item)
        elif os.path.isdir(item):
            for (root, dirs, filenames) in os.walk(item):
                matched_files = [f for f in filenames if pattern_re.match(f)]
                files.extend([os.path.join(root, f) for f in matched_files])
        elif len(os.path.split(item)) > 1 and partial is False:
            files.extend(find_files(os.path.dirname(item), os.path.basename(item), True))

    return files


def find_audits(paths):
    audits = find_files(paths)
    if len(audits) < 1:
        display('No audits to process.', exit=True)
    else:
        s = ''
        if len(audits) > 1: s = 's'
        display('{} audit{} to process.'.format(len(audits), s), verbose=True)
    return sorted(audits)


def update_check_type(line):
    global db_type_re
    types = db_type_re.search(line)
    if types is not None:
        if types.groups()[1] == 'DB2':
            new_type = 'IBM_DB2DB'
        elif types.groups()[1] == 'SQLServer':
            new_type = 'MS_SQLDB'
        elif types.groups()[1] == 'sybase':
            new_type = 'SybaseDB'
        else:
            new_type = '{}DB'.format(types.groups()[1])
        new_line = line.replace(types.groups()[0], new_type)
        return '{}">'.format(new_line[:new_line.index(new_type) + len(new_type)])
    return line


def read_audit_lines(audit):
    global check_type_re, db_type_re
    lines = []

    found = False
    with open(audit, 'r') as a_in:
        while True:
            line = a_in.readline()
            if not line:
                break
            elif found:
                lines.append(line.rstrip())
            else:
                if check_type_re.search(line):
                    if db_type_re.search(line):
                        found = True
                    else:
                        return None
                lines.append(line.rstrip())

    if not found: return None

    return lines


def convert_audit(audit):
    global db_type_re, field_replace_re, group_policy_re, sql_field_re, simple_quoted_field_re, simple_unquoted_field_re, select_re
    display('Processing {}'.format(audit))

    display(' - reading audit', verbose=True)
    lines = read_audit_lines(audit)
    if lines is None:
        display(' * audit not supported')
        return None

    del_lines = []
    sql_request = None
    sql_types = None
    sql_expect = None
    in_item = False
    for i in range(len(lines)):
        if db_type_re.search(lines[i]):
            display(' - updating check type ({})'.format(i + 1), verbose=True)
            lines[i] = update_check_type(lines[i])
        elif group_policy_re.search(lines[i]):
            display(' - adding group policy line to delete ({})'.format(i + 1), verbose=True)
            del_lines.append(i)
        elif sql_field_re.search(lines[i]):
            name = sql_field_re.findall(lines[i])[0][0]
            if name == 'sql_expect':
                sql_expect = i
            elif name == 'sql_types':
                sql_types = i
            elif name == 'sql_request':
                sql_request = i
        elif open_item_re.search(lines[i]):
            if in_item:
                display(' * opening of already open item ({})'.format(i + 1))
            in_item = True
        elif close_item_re.search(lines[i]):
            if not in_item:
                display(' * closing of non-open item ({})'.format(i + 1))
            if sql_types is None or sql_expect is None:
                display(' * did not find sql_types and sql_expect ({})'.format(i + 1))
            else:
                expect_vals = ':'.join(lines[sql_expect].split(':')[1:])
                parsed = sql_util.parse_expect(expect_vals)
                computed = [sql_util.compute_type_and_expect(p) for p in parsed]
                line = '{}{}'.format(field_replace_re.findall(lines[sql_types])[0], ', '.join([c[0] for c in computed]))
                lines[sql_types] = line
                line = '{}{}'.format(field_replace_re.findall(lines[sql_expect])[0], ', '.join([c[1] for c in computed]))
                lines[sql_expect] = line
                if sql_request is not None:
                    parts = lines[sql_request].split(':')
                    value = ':'.join(parts[1:]).strip(' \'"')
                    found = select_re.findall(value)
                    columns = []
                    if len(found) == 1:
                        columns = [i.strip() for i in found[0].split(',')]
                        if len(computed) > 1 and len(computed) != len(columns):
                            display(' * possible mis-match of selected columns and defined values ({}): {} <> {}'.format(sql_request, len(computed), len(columns)))
            sql_request_fields = None
            sql_types = None
            sql_expect = None
            in_item = False
        elif simple_quoted_field_re.search(lines[i]):
            name = lines[i].split(':')[0].strip()
            if name not in ('sql_request', 'info', 'solution', 'description', 'see_also', 'reference'):
                display(' * commenting out unsupported quoted field ({}): {}'.format(i + 1, name))
                lines[i] = '#{}'.format(lines[i])
        elif simple_unquoted_field_re.search(lines[i]):
            name = lines[i].split(':')[0].strip()
            if name not in ('type', 'num_rows', 'severity'):
                display(' * commenting out unsupported unquoted field ({}): {}'.format(i + 1, name))
                lines[i] = '#{}'.format(lines[i])

    if len(del_lines) > 0:
        display(' - deleting lines', verbose=True)
        for i in reversed(sorted(del_lines)):
            del lines[i]

    return '\n'.join(lines)


def write_file(audit, data, output, replace=False):
    if not os.path.isdir(output):
        try:
            os.mkdir(output)
        except:
            display('Unable to create ouput directory: {}'.format(output), exit=True)

    name = os.path.basename(audit)
    filepath = os.path.join(output, name)

    if os.path.isfile(filepath) and not replace:
        display('Unable to overwrite file: {}'.format(filepath), exit=True)

    with open(filepath, 'w') as f_out:
        f_out.write(data + '\n')

    display('Wrote data to file: {}'.format(filepath))


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    display('Start', verbose=True)

    audits = find_audits(args.audit)

    for audit in audits:
        data = convert_audit(audit)
        if data is None:
            continue
        write_file(audit, data, args.output, args.replace)

    display('Done', verbose=True)
