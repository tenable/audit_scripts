# View Audit Structure

## Description

The __view_audit_structure.py__ script is used to visualize the structure of the audit file, most notably the conditional logic of the audit file.

When looking at a downloaded audit file, there is a section in the comment header that defines variables.  The use of these variables are for providing custom input when using Tenable products, and will have no impact when uploading the audit file as a custom audit.

This script is provided as-is to attempt to assist in the debugging of audit files.


## Operation

### Requirements

- python3 (may work on python2.7+, but didn't test)

### Process

- Run the command line python tool to view the struture of the audit file.
    - `./view_audit_structure.py input.audit`

### Usage

```
usage: view_audit_structure.py [-h] [-t] [-v] audit

Display audit structure

positional arguments:
  audit            audit file to view

optional arguments:
  -h, --help       show this help message and exit
  -t, --timestamp  show timestamp on output
  -v, --verbose    show verbose output
```

### Example Run

```Shell Session
test$ ./view_audit_structure.py -tv DISA_STIG_MS_Windows_10_v1r9.audit
2018/09/19 03:55:59 Start
2018/09/19 03:55:59 Reading file values
2018/09/19 03:55:59 Reading DISA_STIG_MS_Windows_10_v1r9.audit
2018/09/19 03:55:59 Computing audit structure
2018/09/19 03:55:59 Outputing structure
2018/09/19 03:55:59   47 <if>
2018/09/19 03:55:59   48 .  <condition type:"AND">
2018/09/19 03:55:59   49 .  .  <custom_item>
2018/09/19 03:55:59   51 .  .  .  Windows 10 is installed
2018/09/19 03:55:59   59 .  <then>
2018/09/19 03:55:59   60 .  .  <report type:"PASSED">
2018/09/19 03:55:59   61 .  .  .  DISA_STIG_MS_Windows_10_v1r9.audit for MS Microsoft Windows 10 from DISA Windows 10 STIG v1r9
2018/09/19 03:55:59   64 .  .  <custom_item>
2018/09/19 03:55:59   66 .  .  .  WN10-CC-000310 - Users must be prevented from changing installation options.
2018/09/19 03:55:59   78 .  .  <report type:"WARNING">
2018/09/19 03:55:59   79 .  .  .  WN10-00-000010 - Domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.
2018/09/19 03:55:59   95 .  .  <custom_item>
2018/09/19 03:55:59   97 .  .  .  WN10-CC-000315 - The Windows Installer Always install with elevated privileges must be disabled.
2018/09/19 03:55:59  109 .  .  <custom_item>
2018/09/19 03:55:59  111 .  .  .  WN10-CC-000320 - Users must be notified if a web-based program attempts to install software.
...
```
