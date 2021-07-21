#!/usr/bin/env python3

# Description : Reads in a directory of shell scripts and generates an
#               audit file with each of the scripts as a
#               CMD_EXEC check.


import argparse
import datetime
import os
import re
import sys


show_verbose = False
show_time = False

setting_re = re.compile('^# *([^ ]+) *: *(.*) *$', re.M)

def parse_args(parameters):
    global show_time, show_verbose

    default_audit = 'output.audit'

    parser = argparse.ArgumentParser(description=('Convert shell scripts '
                                                  'into audit items '))

    parser.add_argument('-t', '--timestamp', action='store_true',
                        help='show timestamp on output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show verbose output')

    parser.add_argument('-o', '--output', nargs=1, default=default_audit,
                        help='output audit name: {}'.format(default_audit))

    parser.add_argument('shell', nargs=1, type=str,
                        help='location of shell files')

    args = parser.parse_args(parameters)

    if args.timestamp:
        show_time = True
    if args.verbose:
        show_verbose = True

    args.output = list_or_string(args.output)
    args.shell = list_or_string(args.shell)

    return args


def list_or_string(target=None):
    if isinstance(target, list):
        if len(target) > 0:
            return target[0]
        else:
            return None
    return target


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


def get_sh_scripts(location):
    exts = ('bash', 'sh', 'ksh', 'txt')
    scripts = []

    if os.path.isdir(location):
        for (root, dirs, files) in os.walk(location):
            for filename in files:
                if filename.split('.')[-1] in exts:
                    scripts.append(os.path.join(root, filename))
    elif os.path.isfile(location):
        if filename.split('.')[-1] in exts:
            scripts.append(os.path.join(location))

    if len(scripts) == 0:
        display('[!] ERROR: source shell location not found', exit=True)

    return scripts


def convert_script_to_item(source, destination=None):
    global setting_re

    basename = '.'.join(os.path.basename(source).split('.')[:-1])

    script = ''
    with open(source, 'r') as s_in:
        script = s_in.read().strip()

    settings = {}
    for key, val in setting_re.findall(script):
        settings[key.lower()] = val

    content = script.replace('\\', '\\\\').replace('"', '\\"')

    desc = settings.get('name', 'CMD: {}'.format(basename))
    expect = settings.get('expect', 'ManualReview').replace('\\', '\\\\').replace('"', '\\"')
    check_type = 'CHECK_{}'.format(settings.get('type', 'REGEX'))

    item = '''<custom_item>
  type          : CMD_EXEC
  description   : "{}"
  cmd           : "{}"
  expect        : "{}"
  dont_echo_cmd : YES
</custom_item>
'''
    check = item.format(desc, content, expect)

    display('[-]   {}: "{}" is expecting "{}"'.format(source, desc, expect))

    return check


def output_audit(items, output):
    content = '''# {}
<check_type:"Unix">

{}

</check_type>'''

    now = datetime.datetime.now()
    audit = content.format(now, '\n\n'.join(items).strip())

    with open(output, 'w') as s_out:
        s_out.write(audit.strip() + '\n')


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    display('[+] Start', verbose=True)

    display('[+] Retrieving shell scripts from "{}"'.format(args.shell))
    scripts = get_sh_scripts(args.shell)
    display('[-]   found {} script{}'.format(len(scripts), 's' * (len(scripts) - 1)))

    items = []
    display('[+] Processing scripts')
    for script in scripts:
        item = convert_script_to_item(script)
        if item is not None:
            items.append(item)

    display('[+] Writing audit: {}'.format(args.output))
    output_audit(items, args.output)

    display('[+] Done', verbose=True)

