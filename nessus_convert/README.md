# .Nessus Convert

## Description

The __nessus_convert.py__ script is used to take an export of a `.nessus` file from a Tenable Compliance scan and generate an exchange format that can be used to import the results into other systems.  The default format is JSON, but also has capability to produce CSV.

This script is provided as-is to attempt to assist in exporting of audit results.


## Operation

### Requirements

- python3 (may work on python2.7+, but didn't test)
- .nessus file for source that contain results to convert

### Process

- Export a `.nessus` file from a compliance scan.
- Run the command line python tool to convert the data to an exchange format.
    - `./nessus_convert.py -f csv complaince_scan.nessus`
    - `./nessus_convert.py -f json complaince_scan.nessus`

### Usage

```
usage: nessus_convert.py [-h] [-f FORMAT] [-i] [-o] [-r] [-t] [-v]
                         files [files ...]

Read .nessus and convert to different format

positional arguments:
  files                 nessus file to update

optional arguments:
  -h, --help            show this help message and exit
  -f FORMAT, --format FORMAT
                        format to output; csv, json
  -i, --include_ids     include internal identifiers
  -o, --overwrite       overwrite output file if it exists
  -r, --rollup          rollup the results
  -t, --timestamp       show timestamp on output
  -v, --verbose         show verbose output
```

### Example Run

```Shell Session
test$ ./nessus_convert.py -tv -f json compliance_scan.nessus
2022/08/03 15:54:14 Processing file: compliance_scan.nessus
2022/08/03 15:54:14 Reading compliance_scan.nessus
2022/08/03 15:54:14 Found 142 results for host 172.26.48.28.
2022/08/03 15:54:14 Writing JSON file: compliance_scan.json
test$
```
