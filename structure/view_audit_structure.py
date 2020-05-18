#!/usr/bin/env python3

# Description : This script will display an audit descriptions with normalized
#               spacing to give a view of how the conditionals line up.


import argparse
import datetime
import re
import sys

regexes = {
  'open': re.compile('^[ \t]*<(item|custom_item|report|if|then|else|condition)[ \t>]'),
  'close': re.compile('^[ \t]*</(item|custom_item|report|if|then|else|condition)[ \t>]'),
  'description': re.compile('^[ \t]*description[ \t]*:[ \t]*["\']')
}

show_verbose = False
show_time = False


def parse_args(parameters):
    global show_time, show_verbose

    parser = argparse.ArgumentParser(description=('Display audit structure'))

    parser.add_argument('-t', '--timestamp', action='store_true',
                        help='show timestamp on output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show verbose output')

    parser.add_argument('audit', type=str, nargs=1,
                        help='audit file to view')

    args = parser.parse_args(parameters)

    if args.timestamp:
        show_time = True
    if args.verbose:
        show_verbose = True

    args.audit = make_list(args.audit)[0]

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


def compute_audit_structure(content=None):
    global regexes
    lines = []
    audit = []
    stack = []

    if content is not None:
        lines = [l.strip() for l in content.split('\n')]
        for n in range(len(lines)):
            if regexes['open'].match(lines[n]):
                finds = regexes['open'].findall(lines[n])
                audit.append((n + 1, len(stack), lines[n]))
                stack.append(finds[0])
            elif regexes['close'].match(lines[n]):
                finds = regexes['close'].findall(lines[n])
                if len(stack) == 0:
                    msg = 'Ran out of stack closing tag: {} (line {})'
                    display(msg.format(finds[0], n), exit=1)
                elif finds[0] == stack[-1]:
                    stack = stack[:-1]
                else:
                    msg = 'Unbalanced tag: {} - {} (line {})'
                    display(msg.format(stack[-1], finds[0], n), exit=2)
            elif regexes['description'].match(lines[n]):
                description = ':'.join(lines[n].split(':')[1:]).strip()[1:-1]
                audit.append((n + 1, len(stack), description))

    return audit


def output_structure(structure=[]):
    width = len(str(structure[-1][0]))
    form = '{:' + str(width) + '} {}{}'

    for (line, depth, text) in structure:
        display(form.format(line, '.  '*depth, text))


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    display('Start', verbose=True)
    display('Reading file values', verbose=True)
    audit = read_file(args.audit)
    display('Computing audit structure', verbose=True)
    structure = compute_audit_structure(audit)
    display('Outputing structure', verbose=True)
    output_structure(structure)
    display('Done', verbose=True)

