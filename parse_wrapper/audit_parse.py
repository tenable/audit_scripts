#!/usr/bin/env python3

# Description : This script is a wrapper around the Nessus command line
#               processors (`nasl`) and the compliance plugins  to view audit
#               file meta-data, which includes syntax errors.  The script uses
#               a feature that is being deployed in plugins that allow the
#               processing of an audit file without the requirement to connect
#               to a target.


import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import xml.etree.ElementTree as ET

show_verbose = False
show_time = False

check_type_re = re.compile('^\\s*<\\s*check_type\\s*:\\s*"([^"]+)".*>')

def parse_args(parameters):
    global show_time, show_verbose

    parser = argparse.ArgumentParser(description=('Use nasl and a plugin to '
                                                  'parse audit files and '
                                                  'display data or export '
                                                  'JSON.'))

    parser.add_argument('-t', '--timestamp', action='store_true',
                        help='show timestamp on output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show verbose output')

    parser.add_argument('-j', '--json', action='store_true',
                        help='display audit as json')
    parser.add_argument('-n', '--nasl', nargs=1, default=None,
                        help='location of nasl executable')
    parser.add_argument('-o', '--output', nargs=1, default=None,
                        help='output for JSON files')
    parser.add_argument('-p', '--plugins', nargs=1, default=None,
                        help='location to find compliance plugins')
    parser.add_argument('-r', '--replace', action='store_true',
                        help='overwrite existing files')

    parser.add_argument('audit', type=str, nargs='+',
                        help='audit file(s) to process')

    args = parser.parse_args(parameters)

    if args.timestamp:
        show_time = True
    if args.verbose:
        show_verbose = True

#    args.filename = make_list(args.filename)[0]
    args.audit = make_list(args.audit)
    if args.nasl is not None:
        args.nasl = make_list(args.nasl)[0]
    if args.output is not None:
        args.output = make_list(args.output)[0]

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
    #display('Finding audits...', verbose=True)
    audits = find_files(paths)
    if len(audits) < 1:
        display('No audits to process.', exit=True)
    else:
        s = ''
        if len(audits) > 1: s = 's'
        display('{} audit{} to process.'.format(len(audits), s), verbose=True)
    return sorted(audits)


def find_nasl(path):
    #display('Find nasl executable', verbose=True)
    nasl = shutil.which('nasl')

    if path is not None and os.path.isfile(path):
        nasl = path
    elif os.getenv('NASL'):
        nasl = os.getenv('NASL')
    elif nasl is None and os.path.isfile('/opt/nessus/bin/nasl'):
        nasl = '/opt/nessus/bin/nasl'

    if nasl is None:
        display('Nessus executable not found.', exit=True)
    else:
        display('Using Nessus executable at {}.'.format(nasl), verbose=True)

    return nasl


def find_plugins(path, nasl):
    #display('Find compliance plugins', verbose=True)
    plugins = {}

    if path is None:
        path = '/opt/nessus/lib/nessus/plugins'

    filenames = find_files(path, '.*compliance_check.*\.nbin$')
    for filename in filenames:
        info = get_plugin_info(filename, nasl)
        key = info.get('compliance_check_type', None)
        if key is None:
            continue
        elif 'compliance_supports_parse_validation' not in info:
            continue
        elif info['compliance_supports_parse_validation'].lower() != 'true':
            continue
        plugins[key] = info

    if plugins == {}:
        display('Compliance plugins are not found.', exit=True)
    else:
        s = ''
        if len(plugins) > 1: s = 's'
        display('Plugin{} supported: {}'.format(s, ', '.join(sorted(list(plugins)))), verbose=True)

    return plugins


def get_plugin_info(filename, nasl):
    info = {
        'file': filename
    }
    command = [nasl, '-VVVVV', filename]
    res = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode > 0:
        display(res.stderr.decode('ascii'), verbose=True)
        display('Error getting info for plugin: {}'.format(filename), exit=True)

    tree = ET.fromstring(res.stdout.decode('ascii'))
    attribs = tree.find('attributes')
    for item in attribs:
        info[item.find('name').text.strip()] = item.find('value').text.strip()

    return info


def get_check_type(audit):
    global check_type_re
    check_type = None
    with open(audit, 'r') as a_in:
        while True:
            line = a_in.readline()
            if not line:
                break
            finds = check_type_re.findall(line)
            if len(finds) > 0:
                check_type = finds[0]
                break
    return check_type


def parse_audit(audit, plugins, nasl):
    data = None

    check_type = get_check_type(audit)

    if check_type not in plugins:
        return None

    display('Running nasl to parse audit: {}'.format(audit), verbose=True)
    with tempfile.TemporaryDirectory() as tmpdirname:
        output = os.path.join(tmpdirname, 'convert.json')
        command = [
            nasl, '-X',
            '-P', 'compliance_parse_input={}'.format(audit),
            '-P', 'compliance_parse_output={}'.format(output),
            plugins[check_type]['file']
        ]
        res = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            with open(output, 'r') as j_in:
                data = json.load(j_in)
        except:
            display(res.stderr.decode('ascii'), verbose=True)
            display('Error parsing audit: {}'.format(audit), exit=True)

    return data


def write_json_file(audit, data, output, replace=False):
    if not os.path.isdir(output):
        try:
            os.mkdir(output)
        except:
            display('Unable to create ouput directory: {}'.format(output), exit=True)

    name = '{}.json'.format(os.path.basename(audit).replace('.audit', ''))
    filepath = os.path.join(output, name)

    if os.path.isfile(filepath) and not replace:
        display('Unable to overwrite file: {}'.format(filepath), exit=True)

    with open(filepath, 'w') as j_out:
        json.dump(data, j_out)

    display('Wrote data to file: {}'.format(filepath), verbose=True)


def display_audit_info(audit, data):
    display('Audit: {}'.format(audit))

    display('Metadata:')
    form = '    {:' + str(max([len(k) for k in data['meta']])) + '} : {}'
    for key in sorted(data['meta']):
        if key in ('variables',):
            continue
        elif isinstance(data['meta'][key], list):
            display(form.format(key, ', '.join(sorted(data['meta'][key]))))
        else:
            display(form.format(key, data['meta'][key]))

    display('Plugin:')
    form = '    {:' + str(max([len(k) for k in data['plugin']])) + '} : {}'
    for key in sorted(data['plugin']):
        display(form.format(key, data['plugin'][key]))

    display('Errors:')
    for item in data['errors']:
        display('    {}'.format(item))


def display_audit_json(audit, data, display_name=False):
    if display_name:
        display('Audit: {}'.format(audit))
    print(json.dumps(data, indent=2))


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    display('Start', verbose=True)

    audits = find_audits(args.audit)
    nasl = find_nasl(args.nasl)
    plugins = find_plugins(args.plugins, nasl)

    for audit in audits:
        data = parse_audit(audit, plugins, nasl)
        if data is None:
            display('Unable to process audit: {}'.format(audit))
        elif args.output is not None:
            write_json_file(audit, data, args.output, args.replace)
        elif args.json:
            display_audit_json(audit, data, len(audits) > 1)
        else:
            display_audit_info(audit, data)

    display('Done', verbose=True)
