# .Nessus to CSV

## Description

The __nessus_to_csv.py__ script is used to take an export of a `.nessus` file from a Tenable Compliance scan and generate a CSV file of the compliance data.

This script is provided as-is to attempt to assist in exporting of audit results.


## Operation

### Requirements

- python3 (may work on python2.7+, but didn't test)
- .nessus file for source that contain results to convert

### Process

- Export a `.nessus` file from a compliance scan.
- Run the command line python tool to create a new .nessus file for import.
    - `./nessus_to_csv.py complaince_scan.nessus`

### Usage

```
usage: nessus_to_csv.py [-h] [-t] [-v] [-o] nessus

Read .nessus and generate CSV of compliance results.

positional arguments:
  nessus           nessus file to use as results

optional arguments:
  -h, --help       show this help message and exit
  -t, --timestamp  show timestamp on output
  -v, --verbose    show verbose output
  -o, --overwrite  overwrite output file if it exists
```

### Example Run

```Shell Session
test$ ./nessus_to_csv.py -tv compliance_scan.nessus
2022/03/17 08:49:33 Start
2022/03/17 08:49:33 Reading nessus file
2022/03/17 08:49:33 Reading compliance_scan.nessus
2022/03/17 08:49:33 Retrieving results
2022/03/17 08:49:33 Outputing CSV file
2022/03/17 08:49:33 Writing compliance_scan.csv
2022/03/17 08:49:33 Done
test$
```
