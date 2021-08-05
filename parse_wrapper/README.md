# Parse Wrapper

## Description

The __audit_parse.py__ script is a wrapper around the Nessus command line processors (`nasl`) and the compliance plugins  to view audit file meta-data, which includes syntax errors.

The script uses a feature that is being deployed in plugins that allow the processing of an audit file without the requirement to connect to a target.  Not all compliance plugin may support the feature required.  To find out what plugins are available to use this feature, run the script with the verbose (`-v`) option and look for something similar to the following to know which plugins are supported.:

```
Plugins supported: Adtran, Alcatel, Cisco, Unix, ...
```

This script is provided as-is to attempt to assist in checking audit files with its native parser to provide feedback on the audit syntax.


## Operation

### Requirements

- python3 (may work on python2.7+, but didn't test)
- valid Nessus Pro or greater install with updated plugins.
- Audit file to analyze

### Process

- Copy the python script to a system that has the requirements.
    - Parameters for nasl and plugin location are provide for non-standard installations.
- Run the command line python tool to analyze the audit file.
    - `./audit_parse.py test_unix_host.audit`
- Examine the output.

### Usage

```
usage: audit_parse.py [-h] [-t] [-v] [-i] [-n NASL] [-o OUTPUT] [-p PLUGINS]
                      [-r]
                      audit [audit ...]

Use nasl and a plugin to parse audit files and display data or export JSON.

positional arguments:
  audit                 audit file(s) to process

optional arguments:
  -h, --help            show this help message and exit
  -t, --timestamp       show timestamp on output
  -v, --verbose         show verbose output
  -j, --json            display audit as json
  -n NASL, --nasl NASL  location of nasl executable
  -o OUTPUT, --output OUTPUT
                        output for JSON files
  -p PLUGINS, --plugins PLUGINS
                        location to find compliance plugins
  -r, --replace         overwrite existing files
```

### Example Run

```Shell Session
test$ ./audit_parse.py -tv bad_test.audit
2021/04/05 16:24:43 Start
2021/04/05 16:24:43 1 audit to process.
2021/04/05 16:24:43 Using Nessus executable at /opt/nessus/bin/nasl.
2021/04/05 16:24:52 Plugins supported: Adtran, Alcatel, Cisco, Unix
2021/04/05 16:24:52 Running nasl to parse audit: bad_test.audit
2021/04/05 16:24:52 Audit: bad_test.audit
2021/04/05 16:24:52 Metadata:
2021/04/05 16:24:52     benchmark_refs : CSCv7, LEVEL
2021/04/05 16:24:52     copyright      : This script is Copyright (C) 2004-2020 and is owned by Tenable, Inc. or an Affiliate thereof.
2021/04/05 16:24:52     date           : dev
2021/04/05 16:24:52     display_name   : Test of Syntax Error
2021/04/05 16:24:52     filename       : bad_test.audit
2021/04/05 16:24:52     labels         : agent, unix
2021/04/05 16:24:52     name           : Test of Syntax Error
2021/04/05 16:24:52     revision       : dev
2021/04/05 16:24:52     type           : TNS
2021/04/05 16:24:52     version        : 0.0.1
2021/04/05 16:24:52 Plugin:
2021/04/05 16:24:52     type : Unix
2021/04/05 16:24:52 Errors:
2021/04/05 16:24:52     Parse error line 50 - unknown token 'ollowing'
2021/04/05 16:24:52     Could not parse the file bad_test.audit
2021/04/05 16:24:52 Done
test$
```
