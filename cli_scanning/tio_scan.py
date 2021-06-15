#!/usr/bin/env python3

import argparse
import json
import re
import os
import time

import xml.etree.ElementTree as ET

from tenable.io import TenableIO


def print_results(nessus_file):

    print('[+] Compliance Results:')

    root = ET.parse(nessus_file).getroot()

    for report_item in root.iter("ReportItem"):
        if report_item.attrib["pluginFamily"] == "Policy Compliance":
            print('\n{}\n'.format(
              report_item.findall('.//description')[0].text
            ))


def get_plugin(file):
    
    with open(file) as fobj:

        for line in fobj:
            plugin = re.findall('<check_type:"(.*?)"', line)
        
            if plugin:
                return plugin[0]

    print(f'[!] ERROR: plugin not detected in {file}. Exiting.')
    exit(-1)
    

def upload_audits(tio, files):
    
    audits = {
        'custom': {
            'add': []
        }
    }

    print(f'[+] Uploading audits')

    for file in files:

        if not os.path.isfile(file):
            print(f'[!] ERROR: file {file} not found. Exiting.')
            exit(-1)

        print(f'    {file}')
        with open(file) as fobj:

            file_id = tio.files.upload(fobj)

            audits['custom']['add'].append({
                'category': get_plugin(file),
                'variables': {
                    'file': file_id
                },
                'file': file_id
            })

    return audits


def scan(access_key, secret_key, scanner, name, targets, template, audit_files, credentials, delete=False):

    tio = TenableIO(access_key, secret_key)

    compliance = upload_audits(tio, audit_files)
    credentials = get_creds(tio, credentials)

    print('[+] Creating scan')
    scan = tio.scans.create(
        name=name,
        template=template,
        targets=targets,
        scanner=scanner,
        credentials=credentials,
        compliance=compliance
    )

    print(json.dumps(scan, indent=2))

    print('[+] Launching scan')
    tio.scans.launch(scan['id'])

    if wait_for_scan(tio, scan['id']) == 'completed':
        print(f'[+] Exporting scan')
        with open(f'{name}.nessus' ,'wb') as reportobj:
            tio.scans.export(scan['id'], fobj=reportobj)
            print(f'    saved to {name}.nessus')
            print_results(f'{name}.nessus')

    else:
        print('[!] ERROR: scan not completed. Exiting')
        exit(-1)

    if delete:
        print('[+] Deleting scan')
        tio.scans.delete(scan['id'])


def wait_for_scan(tio, id):

    while id:

        status = tio.scans.status(id)
        print(f'    {status}')

        if status in ['initializing', 'pending', 'running',]:
            time.sleep(60)

        else:
            return status


def list_creds(access_key, secret_key):

    tio = TenableIO(access_key, secret_key)
    print('[+] Fetching credentials list')
    print(f'{"Name ".ljust(30)}  {"UUID ".ljust(36)}  {"Category ".ljust(30)}  {"Type ".ljust(30)}')
    print(f'{"".ljust(30, "=")}  {"".ljust(36, "=")}  {"".ljust(30, "=")}  {"".ljust(30, "=")}')
    for cred in tio.credentials.list():
        print(f'{cred["name"].ljust(30)}  {cred["uuid"].ljust(36)}  {cred["category"]["name"].ljust(30)}  {cred["type"]["name"].ljust(30)}')


def get_creds(tio, uuids):

    results = {}

    tio_creds = tio.credentials.list()

    for uuid in uuids:
        for tio_cred in tio_creds:
            if tio_cred["uuid"] == uuid:
                if not tio_cred["category"]["id"] in results:
                    results[tio_cred["category"]["id"]] = {}
                if not tio_cred["type"]["id"] in results[tio_cred["category"]["id"]]:
                    results[tio_cred["category"]["id"]][tio_cred["type"]["id"]] = []
                results[tio_cred["category"]["id"]][tio_cred["type"]["id"]].append(
                    { 'id': uuid }
                )

    return results


def parse_args():

    parser = argparse.ArgumentParser()

    parser.add_argument('--access_key', help='Tenable.io -> Settings -> My Account -> API Keys -> Access Key', required=True)
    parser.add_argument('--secret_key', help='Tenable.io -> Settings -> My Account -> API Keys -> Secret Key', required=True)

    parser.add_argument('--list_credentials', action='store_true', help='List Tenable.io saved credentials and exit')

    parser.add_argument('--scan', action='store_true', help='Perform Tenable.io scanList Tenable.io saved credentials and exit')
    parser.add_argument('--audit', nargs='+', help='Audit file to attach to the scan')
    parser.add_argument('--delete', action='store_true', help='Delete scan on completion')
    parser.add_argument('--credential', nargs='+', help='UUID of credential')
    parser.add_argument('--name', help='Name of scan', default='tio_scan.py scan')
    parser.add_argument('--scanner', help='Tenable.io -> Settings -> Sensors -> Linked Scanners')
    parser.add_argument('--target', nargs='+', help='Targets to scan')
    parser.add_argument('--template', help='Scan template to use', default='compliance')

    args = parser.parse_args()

    if args.list_credentials and args.scan:
        parser.print_help()
        parser.exit(status=1, message='\nERROR: can only specify --list_credentials or --scan\n')

    if args.scan:
        if not args.audit:
            parser.print_help()
            parser.exit(status=1, message='\nERROR: --scan requires audit files specified with --audit\n')

        if not len(args.credential):
            parser.print_help()
            parser.exit(status=1, message='\nERROR: --scan requires credentials specified with --credential\n')

        if not len(args.target):
            parser.print_help()
            parser.exit(status=1, message='\nERROR: --scan requires targets specified with --target\n')

    return args


def main():

    args = parse_args()

    if args.list_credentials:
        list_creds(args.access_key, args.secret_key)

    elif args.scan:
        scan(
            args.access_key,
            args.secret_key,
            args.scanner, 
            args.name, 
            args.target, 
            args.template, 
            args.audit,
            args.credential,
            args.delete
        )


if __name__ == '__main__':
    main()
