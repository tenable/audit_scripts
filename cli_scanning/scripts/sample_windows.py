#!/usr/bin/env python3

from tio_scan import scan

################################################################################
# Begin User Defined Variables
################################################################################

# Tenable.io API Keys
# These are generated in Tenable.io -> Settings -> My Account -> API Keys
access_key = 'changeme'
secret_key = 'changeme'

# This setting tells Tenable.io which scanner to use
# The scanner names are found in Tenable.io -> Settings -> Sensors -> Linked Scanners
scanner = 'changeme'

# Scan Name
name = 'test scan'

# Scan Targets
targets = [ '10.0.0.1', ]

# Scan Template to use
template = 'compliance'

# List of Audit Files to attach to the scan
audit_files = [ 'test.audit', ]

credentials = {
    'Host': {
        'Windows': [
            {
                'auth_method': 'Password',
                'username': 'Administrator',
                'password': 'changeme',
                'domain': ''
            }
        ]
    }
}

################################################################################
# End User Defined Variables
################################################################################

scan(access_key, secret_key, scanner, name, targets, template, audit_files, credentials, delete=True)
