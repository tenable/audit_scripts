# DB Audit Migrate

## Description

The __db_audit_migrate.py__ script is a utility to convert audit files that were written for the Database Compliance Check plugin and format them to a new structure to support individual database technology plugins.

This script is provided as-is to attempt to assist in migrating existing database audits to the individual database technology audits.


## Operation

### Requirements

- python3 (may work on python2.7+, but didn't test)
- Audit file to convert

### Process

- Run the command line python tool to convert the audit file.

### Usage

```
usage: db_audit_migrate.py [-h] [-t] [-v] [-o OUTPUT] [-r] audit [audit ...]

Convert Database audits to individual technology database audits.

positional arguments:
  audit                 audit file(s) to process

optional arguments:
  -h, --help            show this help message and exit
  -t, --timestamp       show timestamp on output
  -v, --verbose         show verbose output
  -o OUTPUT, --output OUTPUT
                        output directory for new audits
  -r, --replace         overwrite existing files
```

### Example Run

```Shell Session
test$ ./db_audit_migrate.py -tv CIS_MySQL_8.0_Enterprise_Benchmark_v1.2.0_Level_1_DB.audit
2022/09/13 19:58:00 Start
2022/09/13 19:58:00 1 audit to process.
2022/09/13 19:58:00 Processing CIS_MySQL_8.0_Enterprise_Benchmark_v1.2.0_Level_1_DB.audit
2022/09/13 19:58:00  - reading audit
2022/09/13 19:58:00  - updating check type (39)
2022/09/13 19:58:00  - adding group policy line to delete (40)
2022/09/13 19:58:00  * commenting out unsupported unquoted field (50): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (59): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (159): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (188): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (217): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (252): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (287): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (322): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (357): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (392): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (1411): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (1703): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (1712): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (1811): check_option
2022/09/13 19:58:00  * commenting out unsupported unquoted field (1884): check_option
2022/09/13 19:58:00  - adding group policy line to delete (2065)
2022/09/13 19:58:00  - deleting lines
2022/09/13 19:58:00 Wrote data to file: ./CIS_MySQL_8.0_Enterprise_Benchmark_v1.2.0_Level_1_DB.audit
2022/09/13 19:58:00 Done
test$
```
