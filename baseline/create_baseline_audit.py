#!/usr/bin/env python3

# Description : This script will take a configuration audit and the values
#               from a .nessus file and populate a new audit file with the
#               known_good values assigned.  The new audit can then be used
#               to test a baseline scan against other systems.


import argparse
import datetime
import os
import re
import sys

import xml.etree.ElementTree as ET

regexes = {
  'scon': re.compile('^[\s\t]*<condition[\s\t]+type[\s\t]*:[\s\t]*["\'](and|or)["\'][\s\t]*>[\s\t]*$'),
  'econ': re.compile('^[\s\t]*</condition[\s\t]*>[\s\t]*$'),
  'sitem': re.compile('^[\s\t]*<(item|custom_item)>[\s\t]*$'),
  'eitem': re.compile('^[\s\t]*</(item|custom_item)>[\s\t]*$'),
  'desc': re.compile('^([\s\t]*)description[\s\t]*:.*$'),
  'ctype': re.compile('^[\s\t]*<[\s\t]*check_type[\s\t]*:[\s\t]*"([^"]*)"[\s\t>]', re.M)
}

no_value = '__ObNoXiOuS_StRiNg_ThAt_ShOuLd_NoT_ExIsT__'
show_verbose = False
show_time = False


def parse_args(parameters):
    global show_time, show_verbose

    parser = argparse.ArgumentParser(description=('Read audit file and nessus '
                                                  'file and create a new '
                                                  'baseline audit based on '
                                                  'known good values.'))

    parser.add_argument('-t', '--timestamp', action='store_true',
                        help='show timestamp on output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show verbose output')

    parser.add_argument('-o', '--overwrite', action='store_true',
                        help='overwrite output file if it exists')
    parser.add_argument('-f', '--filename', nargs=1, default='',
                        help='override filename of output file')

    parser.add_argument('audit', type=str, nargs=1,
                        help='audit files to use as source')
    parser.add_argument('nessus', type=str, nargs=1,
                        help='nessus file to use values from')

    args = parser.parse_args(parameters)

    if args.timestamp:
        show_time = True
    if args.verbose:
        show_verbose = True

    args.filename = make_list(args.filename)[0]
    args.audit = make_list(args.audit)[0]
    args.nessus = make_list(args.nessus)[0]

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


def get_values_from_nessus(contents):
    global no_value
    values = {}

    try:
        tree = ET.fromstring(contents)
        for report in tree.findall('Report'):
            for host in report.findall('ReportHost'):
                hostname = host.attrib['name']
                display('Retrieving values from {}'.format(hostname),
                        verbose=True)
                values[hostname] = {}
                for item in host.findall('ReportItem'):
                    description = ''
                    value = no_value
                    for child in item:
                        if 'compliance-check-name' in child.tag:
                            description = child.text.strip()
                        elif 'compliance-actual-value' in child.tag:
                            value = child.text
                    if description and value != no_value:
                        values[hostname][description] = value
    except Exception as e:
        display('ERROR: parsing nessus file: {}'.format(e), exit=1)
        sys.exit(1)

    return values


def create_filename(filename, hostname):
    basefile = '.'.join(filename.split('.')[:-1])
    ext = filename.split('.')[-1]
    return '{}.{}.{}'.format(basefile, hostname, ext)


def strip_quotes(target):
    if isinstance(target, str):
        stripped = target.strip()
        if stripped[0] in '"\'' and stripped[0] == stripped[-1]:
            return stripped[1:-1]
        else:
            return stripped
    elif isinstance(target, list):
        return [strip_quotes(i) for i in target]
    else:
        return target


def get_plugin_from_contents(contents):
    global regexes
    plugin = 'Generic'

    if not isinstance(contents, str):
        return plugin

    matches = regexes['ctype'].findall(contents)
    if len(matches) == 1:
        plugin = matches[0]

    return plugin


def quote_and_escape_value(source, plugin):

    if not isinstance(source, str):
        return source

    if '"' in source and "'" not in source and not plugin in ('Unix',):
        value = "'{}'".format(source)
    else:
        value = '"{}"'.format(source.replace('"', '\\"'))

    return value


def apply_values_to_audit(filename, contents, values):
    global regexes

    audits = {}

    plugin = get_plugin_from_contents(contents)

    lines = contents.split('\n')
    for host in values:
        display('Applying values for {}'.format(host), verbose=True)
        auditname = create_filename(filename, host)
        audit_lines = []
        in_condition = False
        in_item = False
        known_good = ''
        space = ''

        for line in lines:
            if regexes['econ'].match(line):
                in_condition = False

            elif regexes['scon'].match(line):
                in_condition = True

            elif regexes['sitem'].match(line):
                in_item = True

            elif regexes['eitem'].match(line):
                if not known_good == '':
                    value = quote_and_escape_value(known_good, plugin)
                    new_line = '{}known_good : {}'.format(space, value)
                    audit_lines.append(new_line)
                known_good = ''

                in_item = False

            elif regexes['desc'].match(line):
                description = ':'.join(line.split(':')[1:]).strip()
                stripped = strip_quotes(description)

                if stripped in values[host]:
                    known_good = values[host][stripped]
                    space = regexes['desc'].findall(line)[0]

            audit_lines.append(line)

        audits[auditname] = '\n'.join(audit_lines)

    return audits


def output_audits(audits, overwrite, output_file):
    for filename in audits:
        output_name = filename

        if output_file:
            output_name = output_file

        write_file(output_name, audits[filename], overwrite)


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    display('Start')
    display('Reading nessus file')
    nessus = read_file(args.nessus)
    display('Retrieving values')
    values = get_values_from_nessus(nessus)
    display('Reading audit file')
    audit = read_file(args.audit)
    display('Applying values')
    outputs = apply_values_to_audit(args.audit, audit, values)
    display('Outputing file')
    output_audits(outputs, args.overwrite, args.filename)
    display('Done')
