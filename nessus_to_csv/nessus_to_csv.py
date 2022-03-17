#!/usr/bin/env python3

# Description : This script will extract the compliance results from a
#               .nessus export and generate a CSV with the results.


import argparse
import csv
import datetime
import os
import sys

import xml.etree.ElementTree as ET

show_verbose = False
show_time = False


def parse_args(parameters):
    global show_time, show_verbose

    parser = argparse.ArgumentParser(description=('Read .nessus and generate '
                                                  'CSV of compliance results.'))

    parser.add_argument('-t', '--timestamp', action='store_true',
                        help='show timestamp on output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show verbose output')

    parser.add_argument('-o', '--overwrite', action='store_true',
                        help='overwrite output file if it exists')

    parser.add_argument('nessus', type=str, nargs=1,
                        help='nessus file to use as results')

    args = parser.parse_args(parameters)

    if args.timestamp:
        show_time = True
    if args.verbose:
        show_verbose = True

    args.nessus = make_list(args.nessus)[0]

    return args


def make_list(target=None):
    if target is None:
        return []
    elif isinstance(target, list):
        return target
    else:
        return [target]


def display(message, verbose=False, exit_code=0):
    global show_time, show_verbose

    if show_time:
        now = datetime.datetime.now()
        timestamp = datetime.datetime.strftime(now, '%Y/%m/%d %H:%M:%S')
        message = '{} {}'.format(timestamp, message)

    out = sys.stdout
    if exit_code > 0:
        out = sys.stderr

    if verbose and show_verbose:
        out.write(message.rstrip() + '\n')
    elif not verbose:
        out.write(message.rstrip() + '\n')

    out.flush()

    if exit_code > 0:
        sys.exit(exit_code)


def read_file(filename):
    contents = ''
    try:
        display('Reading {}'.format(filename), verbose=True)
        with open(filename, 'r') as file_in:
            contents = file_in.read()
    except Exception as e:
        display('ERROR: read_file(): reading file: {}: {}'.format(filename, e), exit_code=1)

    return contents


field_order = [
    'target',
    'result',
    'check-name',
    'info',
    'solution',
    'see-also',
    'reference',
    'policy-value',
    'actual-value',
    'error'
]

def field_order_key(item):
    global field_order
    try:
        return (field_order.index(item), item.lower())
    except:
        return (999, item.lower())


def write_csv_file(filename, fields, values, overwrite=False):
    output_name = os.path.basename(filename).replace('.nessus', '') + '.csv'

    if os.path.isfile(output_name) and not overwrite:
        display('ERROR: write_csv_file(): file exists: {}'.format(output_name), exit_code=1)

    ordered_fields = sorted(fields, key=field_order_key)

    try:
        display('Writing {}'.format(output_name), verbose=True)
        with open(output_name, 'w') as file_out:
            writer = csv.DictWriter(
                file_out,
                fieldnames=ordered_fields,
                dialect='excel',
                quoting=csv.QUOTE_ALL
            )
            writer.writeheader()
            for value in values:
                writer.writerow(value)
    except Exception as e:
        display('ERROR: write_csv_file(): writing file: {}: {}'.format(output_name, e), exit_code=1)


def get_compliance_data(contents):
    values = []
    fields = set(['target'])

    try:
        tree = ET.fromstring(contents)
        hosts = tree.findall('Report/ReportHost')
        for host in hosts:
            name = host.attrib.get('name', None)
            items = host.findall('ReportItem')
            for item in items:
                is_compliance = item.find('compliance')
                if is_compliance is None:
                    continue

                value = { 'target': name }
                for elem in item:
                    if '{http://www.nessus.org/cm}' not in elem.tag:
                        continue

                    field = elem.tag.replace('{http://www.nessus.org/cm}compliance-', '')
                    if field.endswith('-id'):
                        continue
                    elif field in ('source', 'uname', 'dbtype'):
                        continue

                    fields.add(field)
                    value[field] = elem.text
                values.append(value)
    except Exception as e:
        display('ERROR: get_compliance_data(): {}'.format(e), exit_code=1)

    return values, list(fields)


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    display('Start')
    display('Reading nessus file')
    nessus = read_file(args.nessus)
    display('Retrieving results')
    values, fields = get_compliance_data(nessus)
    display('Outputing CSV file')
    write_csv_file(args.nessus, fields, values, args.overwrite)
    display('Done')
