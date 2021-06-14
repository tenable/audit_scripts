#!/usr/bin/env python3

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
