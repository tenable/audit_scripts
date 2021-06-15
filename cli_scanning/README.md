# Compliance Scanning via CLI

This document outlines the steps involved in running an audit against a target from the CLI via a local Nessus install, or via the Tenable.io API.  Visit the appropriate section for steps to complete the scan:

* [Nessus Scan via CLI](#Nessus-Scan-via-CLI)
* [Tenable.io Scan via CLI](#Tenable.io-Scan-via-CLI)

# Nessus Scan via CLI

Running a CLI scan is much quicker than running a scan from the GUI, and is appropriate for testing/validating syntax of an audit.  This method also allows for quickly testing checks during audit development.

This document applies to both Windows and Linux.

## Setup

These steps need to be performed from an OS with Nessus installed.

1. Locate the audit file to test.

2. Locate the nasl binary (default paths below).
   * Windows: C:\Program Files\Tenable\Nessus\nasl.exe
   * Linux/Unix: /opt/nessus/bin/nasl

3. Locate the appropriate plugin path for the target/audit (default paths below).
   * Window: C:\ProgramData\Tenable\Nessus\nessus\plugins
   * Linux/Unix: /opt/nessus/lib/nessus/plugins

4. Determine which plugin is appropriate for the target/audit.  To get a list of plugins, list `*compliance_check*.nbin` in the plugins directory from step 3.

```
# ls /opt/nessus/lib/nessus/plugins/*compliance_check*.nbin

/opt/nessus/lib/nessus/plugins/adtran_compliance_check.nbin
/opt/nessus/lib/nessus/plugins/alcatel_compliance_check.nbin
...
/opt/nessus/lib/nessus/plugins/compliance_check.nbin ← Windows Compliance Plugin
...
/opt/nessus/lib/nessus/plugins/watchguard_compliance_check.nbin
/opt/nessus/lib/nessus/plugins/zte_compliance_check.nbin
```

## Running on Windows

1. Open an elevated prompt.
2. Run the command below substituting your nasl and plugin paths.

```> “C:\Program Files\Tenable\Nessus\nasl.exe” -t <IP of target> C:\ProgramData\Tenable\Nessus\nessus\plugins\<plugin>```

### Example - Scan Windows target 192.168.1.10 (interactive):

```> “C:\Program Files\Tenable\Nessus\nasl.exe” -t 192.168.1.10 C:\ProgramData\Tenable\Nessus\nessus\plugins\compliance_check.nbin```

```
            Windows Compliance Checks, version 1.327

Which file contains your security policy : C:\audits\server_2019_test.audit
SMB login : Administrator
SMB password : 
SMB hash :
SMB domain (optional) : 
```

## Running on Linux/Unix

1. Open a terminal as root.
2. Run the command below substituting your nasl and plugin paths.

```# /opt/nessus/bin/nasl -t <IP of target> /opt/nessus/lib/nessus/plugins/<plugin>```

### Example - Scan Linux target 192.168.1.1 (interactive):

```# /opt/nessus/bin/nasl -t 192.168.1.11 /opt/nessus/lib/nessus/plugins/unix_compliance_check.nbin```

```
            Unix Compliance Checks, version 1.443

Which file contains your security policy ? /root/centos_9_test.audit
SSH login to connect with : root
How do you want to authenticate ? (key or password) [password] 
SSH password : 
What level of docker support ? (host/containers/all) [host] : 
```

### Example - Scan Linux target 192.168.1.11 (non-interactive)

> WARNING - this method will expose credentials in shell history, and in the process list:
For this method, take all of the parameters entered from the interactive method, combine them within the echo -e “” with a \n following each parameter.

```# echo -e "/root/centos_9_test.audit\nroot\n\npassword\n" | /opt/nessus/bin/nasl -t 192.168.1.11 /opt/nessus/lib/nessus/plugins/unix_compliance_check.nbin```

```
            Unix Compliance Checks, version 1.443

Which file contains your security policy ? SSH login to connect with : How do you want to authenticate ? (key or password) [password] stty: standard input: Inappropriate ioctl for device
SSH password : stty: standard input: Inappropriate ioctl for device

What level of docker support ? (host/containers/all) [host] :
```

## Tips, Tricks and Troubleshooting

* When scanning Windows targets via this method, you need to ensure the ‘Remote Registry’ service is running, and the administrative shares are enabled.

* Currently the Windows CLI does not support passing in arguments through a piped statement (like the Linux example above).

* Syntax highlighting packages for NASL and .audit files are available for the following editors:
Atom package: https://atom.io/packages/language-nasl
Sublime package: https://github.com/tenable/sublimetext-nasl

* There is a utility available at https://github.com/tenable/audit_scripts/tree/master/variables for replacing variables in the audit based on the variable definitions in the audit metadata.

## Sample results

The output of the scan contains similar information to the GUI scan.  Here is an example of a passed check:

```
"Configure Microsoft Defender SmartScreen to block potentially unwanted apps": [PASSED]

This policy setting lets you configure whether to turn on blocking for potentially unwanted apps in Microsoft Defender SmartScreen. Potentially unwanted app blocking in Microsoft Defender SmartScreen provides warning messages to help protect users from adware coin miners bundleware and other low-reputation apps that are hosted by websites. Potentially unwanted app blocking in Microsoft Defender SmartScreen is turned off by default.

If you enable this setting potentially unwanted app blocking in Microsoft Defender SmartScreen is turned on.

If you disable this setting potentially unwanted app blocking in Microsoft Defender SmartScreen is turned off.

If you don't configure this setting users can choose whether to use potentially unwanted app blocking in Microsoft Defender SmartScreen.

This policy is available only on Windows instances that are joined to a Microsoft Active Directory domain; or on Windows 10 Pro or Enterprise instances that are enrolled for device management.

See Also : 

https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v80/ba-p/1233193

Remote value: 1
Policy value: 1

Here is an example of a failed check.  Similar to the GUI, it will also display solution text if the check fails.

"Allow user-level native messaging hosts (installed without admin permissions)": [FAILED]

Enables user-level installation of native messaging hosts.

If you disable this policy Microsoft Edge will only use native messaging hosts installed on the system level.

By default if you don't configure this policy Microsoft Edge will allow usage of user-level native messaging hosts.

Reference(s) : 

800-171|3.4.6,800-171|3.4.7,800-53|CM-7,CN-L3|7.1.3.5(c),CN-L3|7.1.3.7(d),CN-L3|8.1.4.4(b),CSF|PR.IP-1,CSF|PR.PT-3,ITSG-33|CM-7,NIAv2|SS13b,NIAv2|SS14a,NIAv2|SS14c,NIAv2|SS15a,SWIFT-CSCv1|2.3

See Also : 

https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v80/ba-p/1233193

Solution : 

Policy Path: Microsoft Edge\Native Messaging
Policy Setting Name: Allow user-level native messaging hosts (installed without admin permissions)

Remote value: NULL
Policy value: 0

Output filtering

The scan command can be piped into egrep to do advanced filtering based on regex.  If you only want to display descriptions that are PASSED, FAILED or WARNING you can append | egrep '(PASSED|FAILED|WARNING)' to the end of your command, which will produce the following output:

"Allow user-level native messaging hosts (installed without admin permissions)": [FAILED]
"Allow users to proceed from the HTTPS warning page": [FAILED]
"Configure Microsoft Defender SmartScreen to block potentially unwanted apps": [PASSED]
"Configure Microsoft Defender SmartScreen": [FAILED]
"Default Adobe Flash setting": [FAILED]
"Enable saving passwords to the password manager": [FAILED]
"Enable site isolation for every site": [FAILED]
"Control which extensions cannot be installed": [FAILED]
"Minimum TLS version enabled": [FAILED]
"Prevent bypassing Microsoft Defender SmartScreen prompts for sites": [FAILED]
"Prevent bypassing of Microsoft Defender SmartScreen warnings about downloads": [FAILED]
"Supported authentication schemes": [PASSED]
```

## Enable debugging

Debugging can be enabled by adding `<debug />` to the audit file.  As a rule of thumb, I like to add this tag inside the body of the audit, before the first check.

```
<check_type:"Windows" version:"2">
<group_policy:"Microsoft Security Compliance Toolkit">

<debug />

<if>
  <condition type:"OR">
    <custom_item>
      type        : REG_CHECK
      description : "Check if Edge is installed"
      value_type  : POLICY_TEXT
      value_data  : "HKLM\Software\Microsoft\Edge"
      reg_option  : MUST_EXIST
    </custom_item>
```

After this is added, running the audit will give additional detail such as:

```
DEBUG: report_policy_info(): Policy: {
  "check_type" : "<check_type:\"Windows\" version:\"2\">",
  "date" : null,
  "debug" : "<debug />",
  "display_name" : "MSCT Microsoft Edge Version 80 v1.0.0",
  "location" : "/test/test.audit",
  "name" : "test.audit",
  "revision" : null,
  "size" : 3375
}
DEBUG: compliance_init(): smb_session_init()
DEBUG: compliance_init(): Logging in user: Administrator domain: null
DEBUG: compliance_init(): Connecting to ADMIN$ share
DEBUG: compliance_init(): Lexing predefined policies
...
```


# Tenable.io Scan via CLI

## Requirements
* python3
* pytenable package
* tio_scan.py
* credential saved in Tenable.io

The tio_scan.py script allows you to execute compliance scans against targets via the Tenable.io API.

> WARNING - this method will expose Tenable.io api keys in shell history, and in the process list.

There are 2 main modes for the tio_scan.py script.  The first mode is to pass the `--list_credentials` flag.  This will return a list of saved credentials from Tenable.io.  The second mode is to pass the `--scan` flag.  This will create a scan in Tenable.io, scan a target, export the results, and optionally delete the scan.

### List credentials example:

```
# python3 tio_scan.py --access_key <access_key> --secret_key <secret_key> --list_credentials

[+] Fetching credentials list
Name                            UUID                                  Category                        Type                          
==============================  ====================================  ==============================  ==============================
windows-test                    12345678-abcd-4476-917c-1234567890ab  Host                            Windows                       
linux-test                      12345678-abcd-4e12-afe3-1234567890ab  Host                            SSH                           
```

### Scan example:

```
# python3 tio_scan.py --access_key <access_key> --secret_key <secret_key> --scan --target 192.168.1.1 --credential 12345678-abcd-4e12-afe3-1234567890ab --scanner my-scanner --audit test.audit

[+] Uploading audits
    CIS_CentOS_7_Server_L2_v3.0.0.audit
[+] Creating scan
{
  "tag_type": null,
  "container_id": "123456",
  "owner_uuid": "1234-5678",
  "uuid": "template-1234",
  "name": "test scan",
  "description": null,
  "policy_id": 342,
  "scanner_id": null,
  "scanner_uuid": "1234-5678",
  "emails": null,
  "sms": "",
  "enabled": true,
  "include_aggregate": true,
  "scan_time_window": null,
  "custom_targets": "10.0.0.1",
  "target_network_uuid": null,
  "auto_routed": 0,
  "remediation": 0,
  "starttime": null,
  "rrules": null,
  "timezone": null,
  "notification_filters": null,
  "shared": 0,
  "user_permissions": 128,
  "default_permissions": 0,
  "owner": "owner@my-org.com",
  "owner_id": 2,
  "last_modification_date": 1617226095,
  "creation_date": 1617226095,
  "type": "public",
  "id": 345
}
[+] Launching scan
    pending
    running
    completed
[+] Exporting scan
    saved to test scan.nessus
[+] Compliance Results:

"CIS_CentOS_7_Server_L2_v3.0.0.audit from CIS CentOS 7 Benchmark v3.0.0" : [PASSED]

Policy Value:
PASSED

"1.1.1.2 Ensure mounting of squashfs filesystems is disabled - lsmod" : [PASSED]

The squashfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems (similar to cramfs ). A squashfs image can be used without having to first decompress the image.

Rationale:

Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.

Solution:
Edit or create a file in the /etc/modprobe.d/ directory ending in .conf
Example: vi /etc/modprobe.d/squashfs.conf
and add the following line:

install squashfs /bin/true

Run the following command to unload the squashfs module:

# rmmod squashfs

Impact:

Disabling squashfs will prevent the use of snap. Snap is a package manager for Linux for installing Snap packages.

'Snap' application packages of software are self-contained and work across a range of Linux distributions. This is unlike traditional Linux package management approaches, like APT or RPM, which require specifically adapted packages per Linux distribution on an application update and delay therefore application deployment from developers to their software's end-user. Snaps themselves have no dependency on any external store ('App store'), can be obtained from any source and can be therefore used for upstream software deployment. When snaps are deployed on versions of Linux, the Ubuntu app store is used as default back-end, but other stores can be enabled as well.

See Also: https://workbench.cisecurity.org/files/2831

Reference: 800-171|3.4.6,800-171|3.4.7,800-53|CM-7,CN-L3|7.1.3.5(c),CN-L3|7.1.3.7(d),CN-L3|8.1.4.4(b),CSCv7|5.1,CSF|PR.IP-1,CSF|PR.PT-3,ITSG-33|CM-7,LEVEL|2A,NIAv2|SS13b,NIAv2|SS14a,NIAv2|SS14c,NIAv2|SS15a,QCSC-v1|3.2,SWIFT-CSCv1|2.3

Policy Value:
cmd: /sbin/lsmod squashfs | /usr/bin/awk '{print} END {if (NR == 0) print "pass" ; else print "fail"}'
expect: pass
system: Linux

Actual Value:
The command '/sbin/lsmod squashfs | /usr/bin/awk '{print} END {if (NR == 0) print "pass" ; else print "fail"}'' returned : 

Usage: /sbin/lsmod
pass

...

[+] Deleting scan
```
