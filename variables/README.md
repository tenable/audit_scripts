# Replace Variables

## Description

The __replace_variables.py__ script is used to take the values from the out variable definition in the header and place the values in the audit file.  This was test using a custom audit file and an audit file that was downloaded from the Tenable download site.

When looking at a downloaded audit file, there is a section in the comment header that defines variables.  The use of these variables are for providing custom input when using Tenable products, and will have no impact when uploading the audit file as a custom audit.

This script is provided as-is to attempt to make the update of values in the audit file a bit more simple.


## Operation

### Requirements

- python3 (may work on python2.7+, but didn't test)

### Process

- Open the custom audit file or downloaded audit file in a text editor.
- Find the commented variable definition at the top of the audit file that looks like XML.
    - Find the variable name as <name>VARIABLE</name>
    - Update the value you want to replace the variables with in <default>VALUE</default>
- Save and close the text editor.
- Run the command line python tool to create a new file from the updated audit:
    - `./replace_variables.py -f output.audit input.audit`

### Usage

```
usage: replace_variables.py [-h] [-t] [-v] [-o] [-f FILENAME] audit

Replace variable values an audit file with the default values in the header.

positional arguments:
  audit                 nessus file to use values from

optional arguments:
  -h, --help            show this help message and exit
  -t, --timestamp       show timestamp on output
  -v, --verbose         show verbose output
  -o, --overwrite       overwrite output file if it exists
  -f FILENAME, --filename FILENAME
                        override filename of output file
```

Options exist that allow the overwriting of the resulting audit, naming the resulting audit (when only one host is scanned), and providing more verbose output.

### Example Run

```Shell Session
test$ ../replace_variables.py -tv -f test.audit example_CIS_RHEL7.audit
2018/03/28 16:53:31 Start
2018/03/28 16:53:31 Reading file values
2018/03/28 16:53:31 Reading example_CIS_RHEL7.audit
2018/03/28 16:53:31 Identifying variables
2018/03/28 16:53:31 Found variable @GDM_BANNER_MESSAGE@ = Authorized uses only. All activity may be monitored and reported.
2018/03/28 16:53:31 Found variable @HOSTS_ALLOW_NETWORK@ = 192.168.0.0/255.255.0.0
2018/03/28 16:53:31 Found variable @NTP_SERVER@ = 10.0.0.2
2018/03/28 16:53:31 Found variable @SYSLOG_SERVER@ = 10.0.0.2
2018/03/28 16:53:31 Replacing values
2018/03/28 16:53:31 Replacing @GDM_BANNER_MESSAGE@ with "Authorized uses only. All activity may be monitored and reported." at line 973.
2018/03/28 16:53:31 Replacing @NTP_SERVER@ with "10.0.0.2" at line 1352.
2018/03/28 16:53:31 Replacing @NTP_SERVER@ with "10.0.0.2" at line 1353.
2018/03/28 16:53:31 Replacing @NTP_SERVER@ with "10.0.0.2" at line 1545.
2018/03/28 16:53:31 Replacing @NTP_SERVER@ with "10.0.0.2" at line 1546.
2018/03/28 16:53:31 Replacing @HOSTS_ALLOW_NETWORK@ with "192.168.0.0/255.255.0.0" at line 2976.
2018/03/28 16:53:31 Replacing @SYSLOG_SERVER@ with "10.0.0.2" at line 3286.
2018/03/28 16:53:31 Replacing @SYSLOG_SERVER@ with "10.0.0.2" at line 3295.
2018/03/28 16:53:31 Outputing file
2018/03/28 16:53:31 Writing test.audit
2018/03/28 16:53:31 Done
test$
test$ diff example_CIS_RHEL7.audit test.audit
973c973
<           expect      : "^[\\s]*banner-message-text[\\s]*=[\\s]*.@GDM_BANNER_MESSAGE@.[\\s]*$"
---
>           expect      : "^[\\s]*banner-message-text[\\s]*=[\\s]*.Authorized uses only. All activity may be monitored and reported..[\\s]*$"
1352,1353c1352,1353
<           regex       : "^[\\s]*server[\\s]+@NTP_SERVER@"
<           expect      : "^[\\s]*server[\\s]+@NTP_SERVER@"
---
>           regex       : "^[\\s]*server[\\s]+10.0.0.2"
>           expect      : "^[\\s]*server[\\s]+10.0.0.2"
1545,1546c1545,1546
<           regex       : "^[\\s]*(server|pool)[\\s]+@NTP_SERVER@"
<           expect      : "^[\\s]*(server|pool)[\\s]+@NTP_SERVER@"
---
>           regex       : "^[\\s]*(server|pool)[\\s]+10.0.0.2"
>           expect      : "^[\\s]*(server|pool)[\\s]+10.0.0.2"
2976c2976
<       expect      : "^[\\s]*ALL[\\s]*:[\\s]*@HOSTS_ALLOW_NETWORK@[\\s]*$"
---
>       expect      : "^[\\s]*ALL[\\s]*:[\\s]*192.168.0.0/255.255.0.0[\\s]*$"
3286c3286
<           expect      : ".*?:[\\s]*\\*\\.\\*[\\s]+\\@\\@@SYSLOG_SERVER@[\\s]*$"
---
>           expect      : ".*?:[\\s]*\\*\\.\\*[\\s]+\\@\\@10.0.0.2[\\s]*$"
3295c3295
<               expect      : "^[\\s]*inet[\\s]+@SYSLOG_SERVER@/"
---
>               expect      : "^[\\s]*inet[\\s]+10.0.0.2/"
test$
```
