#!/usr/bin/env python3

# Description : This script will add the host properties from one .nessus
#               file into another.  This is to support the import of an
#               offline configuration result file into Tenable.SC.


import argparse
import datetime
import os
import re
import sys

import xml.etree.ElementTree as ET

show_verbose = False
show_time = False


def parse_args(parameters):
    global show_time, show_verbose

    parser = argparse.ArgumentParser(description=('Read template .nessus and '
                                                  'offline .nessus to insert '
                                                  'host properties into '
                                                  'offline nessus.'))

    parser.add_argument('-t', '--timestamp', action='store_true',
                        help='show timestamp on output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show verbose output')

    parser.add_argument('-o', '--overwrite', action='store_true',
                        help='overwrite output file if it exists')
    parser.add_argument('-f', '--filename', nargs=1, default='',
                        help='override filename of output file')

    parser.add_argument('template', type=str, nargs=1,
                        help='nessus file to use as template')
    parser.add_argument('nessus', type=str, nargs=1,
                        help='nessus file to use as results')

    args = parser.parse_args(parameters)

    if args.timestamp:
        show_time = True
    if args.verbose:
        show_verbose = True

    args.filename = make_list(args.filename)[0]
    args.template = make_list(args.template)[0]
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
        display('ERROR: read_file(): reading file: {}: {}'.format(filename, e), exit=1)

    return contents


def write_file(filename, content, overwrite=False):
    if os.path.isfile(filename) and not overwrite:
        display('ERROR: write_file(): file exists: {}'.format(filename), exit=1)

    try:
        display('Writing {}'.format(filename), verbose=True)
        with open(filename, 'w') as file_out:
            file_out.write(str(content))
    except Exception as e:
        display('ERROR: write_file(): writing file: {}: {}'.format(filename, e), exit=1)


def get_host_properties_from_nessus(contents):
    values = {}

    try:
        tree = ET.fromstring(contents)
        host = tree.find('Report/ReportHost')
        name = host.attrib.get('name', None)
        props = host.find('HostProperties')
        values[name] = props
    except Exception as e:
        display('ERROR: get_host_properties_from_nessus(): {}'.format(e), exit=1)
        sys.exit(1)

    display('Host Name: {}'.format(name), verbose=True)

    return values


def create_filename(source, override):
    filename = override

    if not filename:
        basefile = '.'.join(source.split('.')[:-1])
        ext = source.split('.')[-1]
        filename = '{}.{}.{}'.format(basefile, 'offline_import', ext)

    display('Using filename of {}'.format(filename), verbose=True)

    return filename


def unixtime(date):
    epoch = datetime.datetime(1970,1,1)
    return (date - epoch).total_seconds()


def apply_values_to_nessus(contents, values):
    start = datetime.datetime.now()
    end = datetime.datetime.now() + datetime.timedelta(0,1)

    try:
        tree = ET.fromstring(contents)

        name = None
        prefs = tree.findall('Policy/Preferences/PluginsPreferences/item')
        for pref in prefs:
            pref_name = pref.find('preferenceName').text
            pref_selected = pref.find('selectedValue').text
            if 'Offline config file' in pref_name and pref_selected:
                name = pref_selected

        if not name:
            raise Exception('Unable to find the config name.')

        for host in values:
            display('Apply values: {}'.format(host), verbose=True)

            # update TARGET preference
            preferences = tree.find('Policy/Preferences/ServerPreferences')
            for preference in preferences.findall('preference'):
                if preference.find('name').text == 'TARGET':
                    old = preference.find('value').text
                    preference.find('value').text = host
                    break

            report_hosts = tree.findall('Report/ReportHost')
            for report_host in report_hosts:
                report_name = report_host.attrib['name']
                display('Analyzing report: {}'.format(report_name), verbose=True)
                if report_name.lower() == name.lower():
                    display('Found report name: {}'.format(name), verbose=True)
                    report_host.attrib['name'] = host

                    old_props = report_host.find('HostProperties')
                    for tag in old_props.findall('tag'):
                        old_props.remove(tag)

                    new_props = values[host]
                    for tag in new_props.findall('tag'):
                        if tag.attrib['name'] == 'HOST_START_TIMESTAMP':
                            tag.text = str(unixtime(start))
                        elif tag.attrib['name'] == 'HOST_END_TIMESTAMP':
                            tag.text = str(unixtime(end))
                        elif tag.attrib['name'] == 'HOST_START':
                            tag.text = start.strftime('%c')
                        elif tag.attrib['name'] == 'HOST_END':
                            tag.text = end.strftime('%c')

                        old_props.append(tag)

    except Exception as e:
        display('ERROR: apply_values_to_nessus(): {}'.format(e), exit=1)
        sys.exit(1)

    new_content = ET.tostring(tree, encoding='ascii', method='xml', short_empty_elements=False)

    nessus_content = sanitize_xml_to_nessus(new_content)

    return nessus_content


# Warning!!! hackish starts here... really bad.
def sanitize_xml_to_nessus(source):
    content = source.decode('utf-8')

    # clean up xml
    content = content.replace('\'1.0\' encoding=\'ascii\'', '"1.0" ')
    content = content.replace(' xmlns:ns0="http://www.nessus.org/cm"', '')
    content = content.replace('<ns0:', '<cm:')
    content = content.replace('</ns0:', '</cm:')

    content = re.sub('<(Report name="[^"]*")>', '<\\1 xmlns:cm="http://www.nessus.org/cm">', content)


    # clean up character encoding
    finds = re.findall('>([^<]+)<', content)
    for value in finds:
        replace = value.replace('\'', '&apos;')
        replace = replace.replace('"', '&quot;')
        content = content.replace('>' + value + '<', '>' + replace + '<')

    return content


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    display('Start')
    display('Reading template nessus file')
    nessus = read_file(args.template)
    display('Retrieving properties')
    values = get_host_properties_from_nessus(nessus)
    display('Reading offline nessus file')
    content = read_file(args.nessus)
    display('Applying values')
    output = apply_values_to_nessus(content, values)
    display('Outputing file')
    filename = create_filename(args.nessus, args.filename)
    write_file(filename, output, args.overwrite)
    display('Done')
