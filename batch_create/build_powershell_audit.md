# Build Powershell Audit

## Description

The __build_powershell_audit.py__ script reads a directory of powershell scripts with extensions of `.ps1` and creates an audit the will run each of the scripts.

If done manually, a shell script would be pasted into a `AUDIT_POWERSHELL` style Windows check in the `powershell_args` field.  The value would have to be wrapped with single quotes (') and any single quotes inside the script being pasted in would have to be escaped with a backslash (\').

The script will take advantage of comments placed inside the powershell scripts to provide additional operation or more descriptive values.  The comments are in the form of `# key: value`.  The script will take the key and use it for a part of the check.  The following keys are availabl:

* `name`: sets the value as the description of the check.  The default is to use the name of the powershell file.
* `expect`: sets the value as the value to expect in the output.  The default is to use "ManualReview", which tends to fail each check.
* `check_type`: uses the value to help set the type of AUDIT_POWERSHEL evaluation that should happen.  The default is `REGEX` which uses the expected value as a regular expression.

This script is provided as-is to attempt to assist in batch creation of an audit file from powershell scripts.

## Operation

### Requirements

- python3 (may work on python2.7+, but didn't test)
- directory of powershell scripts

### Process

- Copy the python script to a system that has the powershell scripts
- Run the python script with the directory name.
    - `./build_powershell_audit.py powershell_scripts`
- Use the resulting audit file 

### Usage

```
usage: build_powershell_audit.py [-h] [-E] [-t] [-v] [-o OUTPUT]
                                 powershell

Convert powershell scripts into audit items

positional arguments:
  powershell            location of powershell files

optional arguments:
  -h, --help            show this help message and exit
  -E, --encode          encode checks into base64
  -t, --timestamp       show timestamp on output
  -v, --verbose         show verbose output
  -o OUTPUT, --output OUTPUT
                        output audit name
```

### Example Run

```Shell Session
test$ ./build_powershell_audit.py powershell_scripts
[+] Retrieving powershell scripts from "powershell_scripts"
[-]   found 2 scripts
[+] Processing scripts
[-]   powershell_scripts/check_smtp.ps1: "Check SMTP is installed and running" is expecting "ManualReview"
[-]   powershell_scripts/check_www_not_installed.ps1: "Check WWW is not installed" is expecting "Not Installed"
[+] Writing audit: output.audit
```
