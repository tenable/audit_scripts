#!/usr/bin/env python3

# Description : Read in a .nessus file with compliance results and
#               output in specified format.

import argparse
import csv
import datetime
import json
import os
import sys

import xml.etree.ElementTree as ET

show_verbose = False
show_time = False

formats = [ 'csv', 'json' ]

result_value = {
    'ERROR': 4,
    'FAILED': 3,
    'WARNING': 2,
    'PASSED': 1,
}

field_order = [
    'target',
    'result',
    'check_name',
    'info',
    'solution',
    'see_also',
    'reference',
    'policy_value',
    'actual_value',
    'error'
]


def field_order_key(item):
    global field_order
    try:
        return (field_order.index(item), item.lower())
    except:
        return (999, item.lower())


def parse_args(parameters):
    global show_time, show_verbose, formats

    parser = argparse.ArgumentParser(description='Read .nessus and convert to different format')

    parser.add_argument('-f', '--format', type=str, nargs=1, default=[ 'json' ],
                        help='format to output; {}'.format(', '.join(formats)))

    parser.add_argument('-i', '--include_ids', action='store_true',
                        help='include internal identifiers')
    parser.add_argument('-o', '--overwrite', action='store_true',
                        help='overwrite output file if it exists')
    parser.add_argument('-r', '--rollup', action='store_true',
                        help='rollup the results')
    parser.add_argument('-t', '--timestamp', action='store_true',
                        help='show timestamp on output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show verbose output')

    parser.add_argument('files', type=str, nargs='+',
                        help='nessus file to update')

    args = parser.parse_args(parameters)

    if args.timestamp:
        show_time = True
    if args.verbose:
        show_verbose = True

    args.format = args.format[0]

    if args.format not in formats:
        display('ERROR: Unknown file format: {}'.format(args.format), exit_code=1)

    return args


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


def get_compliance_data(contents):
    data = []

    try:
        tree = ET.fromstring(contents)
        reports = tree.findall('Report')
        report_name = reports[0].attrib.get('name', None)

        hosts = tree.findall('Report/ReportHost')
        for host in hosts:
            hostname = host.attrib.get('name', None)

            value = {
                'target': hostname,
                'report': report_name,
            }

            tags = host.findall('HostProperties/tag')
            for tag in tags:
                tag_name = tag.attrib.get('name', None)
                if tag_name in ('host-fqdn', 'host-ip', 'HOST_START_TIMESTAMP', 'HOST_END_TIMESTAMP'):
                    tag_name = tag_name.lower().replace('-', '_')
                    if 'timestamp' in tag_name:
                        value[tag_name.replace('_timestamp', '')] = int(tag.text)
                    else:
                        value[tag_name] = tag.text

            value['results'] = []
            items = host.findall('ReportItem')
            for item in items:
                is_compliance = item.find('compliance')
                if is_compliance is None:
                    continue

                comp = {
                    'plugin_id': item.attrib['pluginID'],
                    'plugin_name': item.attrib['pluginName']
                }
                for elem in item:
                    if '{http://www.nessus.org/cm}' not in elem.tag:
                        continue

                    field = elem.tag.replace('{http://www.nessus.org/cm}compliance-', '')
                    if field in ('source', 'uname', 'dbtype'):
                        continue

                    comp[field.replace('-', '_')] = elem.text
                value['results'].append(comp)
            data.append(value)
    except Exception as e:
        display('ERROR: get_compliance_data(): {}'.format(e), exit_code=1)

    return data


def collapse(data):
    global result_value

    desc = ''
    for i in range(min([len(data[0]['check_name']), len(data[1]['check_name'])])):
        if data[0]['check_name'][i] != data[1]['check_name'][i]:
            break
        desc += data[0]['check_name'][i]

    if ' - ' in desc:
        desc = ' - '.join(desc.split(' - ')[:-1])

    collapsed = {
        'check_name': desc
    }
    refs = set()
    actuals = []
    for item in data:
        short_desc = ''
        actual_desc = ''
        actual_value = ''
        for k in item:
            if k == 'reference':
                refs.update(item[k].split(','))
            elif k == 'result':
                actual_desc = 'ERROR'
                if k not in collapsed:
                    collapsed[k] = item[k]
                elif result_value[item[k]] > result_value[collapsed[k]]:
                    collapsed[k] = item[k]
            elif k == 'check_name':
                short_desc = item[k].replace(desc, '')
            elif k in ('actual_value', 'error'):
                actual_value = ''
                if item[k] is not None:
                    for line in item[k].split('\n'):
                        actual_value += '\n  {}'.format(line.replace('{}', '{{}}'))
            elif k not in collapsed:
                collapsed[k] = item[k]
            elif item[k] != collapsed[k]:
                collapsed[k] = 'multiple'
            elif item[k] == collapsed[k]:
                continue
            else:
                display('WARNING: Unknown result key: {}'.format(k))
        actuals.append('{} {}:{}'.format(actual_desc, short_desc.strip(), actual_value))


    collapsed['reference'] = ','.join(sorted(refs))
    if collapsed['result'] == 'ERROR':
        collapsed['error'] = '\n'.join(actuals)
    else:
        collapsed['actual_value'] = '\n'.join(actuals)

    return collapsed


def rollup(data):
    rolledup_data = []
    controls = {}
    for value in data:
        control = value.get('control_id')
        if control is None:
            display('ERROR: No control found in result.',  exit_code=1)
        if control not in controls:
           controls[control] = []
        controls[control].append(value)

    for control in controls:
        if len(controls[control]) == 1:
            rolledup_data.append(controls[control][0])
        elif len(controls[control]) > 1:
            rolledup_data.append(collapse(controls[control]))
        else:
            display('ERROR: No data available for rollup.',  exit_code=1)

    return rolledup_data


def sanitize_ids(data):
    new_data = []

    for item in data:
        new_item = {}
        for k in item:
            if k[-3:] != '_id':
                new_item[k] = item[k]
        new_data.append(new_item)
        
    return new_data


def write_data(filename, file_format, data):
    new_file = '.'.join(filename.split('.')[:-1]) + '.' + file_format
    if os.path.isfile(new_file) and not args.overwrite:
        display('WARNING: File exists, not writing: {}'.format(new_file))
        return

    if file_format.lower() == 'csv':
        write_csv(new_file, data)
    elif file_format.lower() == 'json':
        write_json(new_file, data)


def write_csv(filename, data):
    display('Writing CSV file: {}'.format(filename), verbose=True)

    fields = set(['target'])
    values = []
    for host in data:
        target = host['target']
        for item in host['results']:
            fields.update(item.keys())
            item['target'] = target
            values.append(item)

    ordered_fields = sorted(fields, key=field_order_key)


    try:
        with open(filename, 'w') as cout:
            writer = csv.DictWriter(
                cout,
                fieldnames=ordered_fields,
                dialect='excel',
                quoting=csv.QUOTE_ALL
            )
            writer.writeheader()
            for value in values:
                writer.writerow(value)
    except Exception as e:
        display('ERROR: write_csv_file(): writing file: {}: {}'.format(filename, e), exit_code=1)


def write_json(filename, data):
    display('Writing JSON file: {}'.format(filename), verbose=True)
    with open(filename, 'w') as jout:
        json.dump(data, jout)


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])

    for filename in args.files:
        display('Processing file: {}'.format(filename))
        nessus = read_file(filename)
        data = get_compliance_data(nessus)
        for host in data:
            display('Found {} results for host {}.'.format(len(host['results']), host['target']), verbose=True)

            if args.rollup:
                host['results'] = rollup(host['results'])
                display('Rolling up results to {}.'.format(len(host['results'])))

            if not args.include_ids:
                host['results'] = sanitize_ids(host['results'])
            else:
                display('Retaining internal identifiers.')

        write_data(filename, args.format, data)
