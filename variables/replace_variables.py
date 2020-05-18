#!/usr/bin/env python3

# Description : This script will examine an audit file for variable usage and
#               provide a method to replace with default or custom values.


import argparse
import datetime
import os
import re
import sys

regexes = {
  'vars': re.compile('^[ \t]*#[ \t]*<variable>.*?^[ \t]*#[ \t]*</variable>', re.M|re.S),
  'name': re.compile('^[ \t]*#[ \t]*<name>(.*?)</name>', re.M),
  'dflt': re.compile('^[ \t]*#[ \t]*<default>(.*?)</default>', re.M)
}

show_verbose = False
show_time = False


def parse_args(parameters):
    global show_time, show_verbose

    parser = argparse.ArgumentParser(description=('Replace variable values '
                                                  'an audit file with the '
                                                  'default values in the '
                                                  'header.'))

    parser.add_argument('-t', '--timestamp', action='store_true',
                        help='show timestamp on output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show verbose output')

    parser.add_argument('-o', '--overwrite', action='store_true',
                        help='overwrite output file if it exists')
    parser.add_argument('-f', '--filename', nargs=1, default='',
                        help='override filename of output file')

    parser.add_argument('audit', type=str, nargs=1,
                        help='nessus file to use values from')

    args = parser.parse_args(parameters)

    if args.timestamp:
        show_time = True
    if args.verbose:
        show_verbose = True

    args.audit = make_list(args.audit)[0]
    args.filename = make_list(args.filename)[0]

    return args


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


def make_list(target=None):
    if target is None:
        return []
    elif isinstance(target, list):
        return target
    else:
        return [target]


def read_file(filename):
    contents = ''
    try:
        display('Reading {}'.format(filename), verbose=True)
        with open(filename, 'r') as file_in:
            contents = file_in.read()
    except Exception as e:
        display('ERROR: reading file: {}: {}'.format(filename, e), exit=1)

    return contents


def write_file(filename, content, overwrite=False):
    if os.path.isfile(filename) and not overwrite:
        display('ERROR: file exists: {}'.format(filename), exit=1)
    
    try:
        display('Writing {}'.format(filename), verbose=True)
        with open(filename, 'w') as file_out:
            file_out.write(content)
    except Exception as e:
        display('ERROR: writing file: {}: {}'.format(filename, e), exit=1)


def get_variables(content=None):
    global regexes
    variables = {}

    if content is not None:
        values = regexes['vars'].findall(content)
        for var in values:
            name = None
            value = None
            names = regexes['name'].findall(var)
            values = regexes['dflt'].findall(var)
            if len(names) == 1:
                name = names[0]
            if len(values) == 1:
                value = values[0]

            if name is not None and value is not None:
                display('Found variable @{}@ = {}'.format(name, value),
                        verbose=True)
                variables[name] = value
            else:
                display('ERROR: Invalid variable @{}@ = {}'.format(name, value),
                        exit=1)

    return variables


def replace_variable_values(content, variables):
    lines = content.split('\n')
    msg = 'Replacing {} with "{}" at line {}.'
    old = []

    for i in range(len(lines)):
        line = lines[i]
        if '@' in line:
            for var in variables:
                name = '@{}@'.format(var)
                if name in line and line.strip()[0] != '#':
                    display(msg.format(name, variables[var], i + 1),
                            verbose=True)
                    line = line.replace(name, variables[var])

                if name in line and line.strip()[0] == '#':
                    parts = line.split('"')
                    old.append({
                        'name': var,
                        'field': parts[3],
                        'value': parts[1]
                    })


        if len(old) > 0:
            remove = []
            for n in range(len(old)):
                field = old[n]['field']
                if re.match('^[ \t]*' + field + '[ \t]*:', line):
                    old_val = old[n]['value']
                    new_val = variables[old[n]['name']]
                    line = line.replace(old_val, new_val)
                    remove.append(n)

            for r in sorted(remove, reverse=True):
                del old[r]

        lines[i] = line

    return '\n'.join(lines)


def output_audit(content, output_file, overwrite=False):
    if output_file:
        write_file(output_file, content, overwrite)
    else:
        print(content)


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    display('Start', verbose=True)
    display('Reading file values', verbose=True)
    audit = read_file(args.audit)
    display('Identifying variables', verbose=True)
    variables = get_variables(audit)
    display('Replacing values', verbose=True)
    replaced = replace_variable_values(audit, variables)
    display('Outputing file', verbose=True)
    output_audit(replaced, args.filename, args.overwrite)
    display('Done', verbose=True)

