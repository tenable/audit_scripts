# Build Shell Script Audit

## Description

The __build_cmd_exec_audit.py__ script reads a directory of shell scripts with extensions of `.bash`, `.sh`, `.ksh`, or `txt`, and creates an audit the will run each of the scripts.

If done manually, a shell script would be pasted into a `CMD_EXEC` style Unix check in the `cmd` field.  The value would have to be wrapped with double quotes (") and any double quotes inside the script being pasted in would have to be escaped with a backslash (\").

The script will take advantage of comments placed inside the shell scripts to provide additional operation or more descriptive values.  The comments are in the form of `# key: value`.  The script will take the key and use it for a part of the check.  The following keys are availabl:

* `name`: sets the value as the description of the check.  The default is to use the name of the cmd_exec file.
* `expect`: sets the value as the value to expect in the output.  The default is to use "ManualReview", which tends to fail each check.

This script is provided as-is to attempt to assist in batch creation of an audit file from shell scripts.

## Operation

### Requirements

- python3 (may work on python2.7+, but didn't test)
- directory of shell scripts

### Process

- Copy the python script to a system that has the shell scripts
- Run the python script with the directory name.
    - `./build_cmd_exec_audit.py shell_scripts`
- Use the resulting audit file 

### Usage

```
usage: build_cmd_exec_audit.py [-h] [-t] [-v] [-o OUTPUT] shell

Convert shell scripts into audit items

positional arguments:
  shell                 location of shell files

optional arguments:
  -h, --help            show this help message and exit
  -t, --timestamp       show timestamp on output
  -v, --verbose         show verbose output
  -o OUTPUT, --output OUTPUT
                        output audit name: output.audit
```

### Example Run

```Shell Session
test$ ./build_cmd_exec_audit.py shell_script
[+] Retrieving shell scripts from "sh_meta"
[-]   found 2 scripts
[+] Processing scripts
[-]   shell_script/check_smtp.txt: "Check SMTP is installed and running" is expecting "ManualReview"
[-]   shell_script/check_www_not_installed.txt: "Check WWW is not installed" is expecting "Not Installed"
[+] Writing audit: output.audit
```
