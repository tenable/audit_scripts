# Offline To SC

## Description

The __offline_to_sc.py__ script is used to take the properties from a .nessus file and place them in a 2nd .nessus file to allow it to be imported into Tenable.sc.

Tenable.sc does not support offline compliance scanning due to the requirement of the scan results to include an IP address that can exist in one of the repositories.  This script is a hack that will use a .nessus export from Tenable.sc to set the address and properties in a .nessus export from Tenable.io or Nessus.  It will also set the start and end properties for the target to be the time of running the script.

This script is provided as-is to attempt to assist in importing audit results into Tenable.sc.


## Operation

### Requirements

- python3 (may work on python2.7+, but didn't test)
- .nessus file for template that contain results from a single target
- .nessus file for source that contain results from a single offline target
- Audit file used in offline must be selected or imported into SC for use and creation of plugins.

### Process

- In Tenable.sc, create a policy to accept the offline scan results.  The policy should be a Policy Compliance Template, with the same audit added to the policy.  Run a scan with this policy against the single IP address, which will produce no compliance results, but may have vulnerabilty or detection results.  This scan is setting up Tenable.sc to accept the offline compliance results.  Download the scan results to use as a template .nessus file.
- In Tenable.io or Nessus, run an offline compliance scan and export a .nessus of the results to use as a source. Like the template .nessus, this scan will contain only a single result set to bind to the single asset from the template.
- Run the command line python tool to create a new .nessus file for import.
    - `./offline_to_sc.py results_from_sc.nessus offline_results.nessus`
- Import the new file into Tenable.sc.

### Usage

```
usage: offline_to_sc.py [-h] [-t] [-v] [-o] [-f FILENAME] template nessus

Read template .nessus and offline .nessus to insert host properties into
offline nessus.

positional arguments:
  template              nessus file to use as template
  nessus                nessus file to use as results

optional arguments:
  -h, --help            show this help message and exit
  -t, --timestamp       show timestamp on output
  -v, --verbose         show verbose output
  -o, --overwrite       overwrite output file if it exists
  -f FILENAME, --filename FILENAME
                        override filename of output file
```

### Example Run

```Shell Session
test$ ./offline_to_sc.py -tv results_from_sc.nessus offline_results.nessus
2019/03/28 08:36:21 Start
2019/03/28 08:36:21 Reading template nessus file
2019/03/28 08:36:21 Reading results_from_sc.nessus
2019/03/28 08:36:21 Retrieving properties
2019/03/28 08:36:21 Reading offline nessus file
2019/03/28 08:36:21 Reading offline_results.nessus
2019/03/28 08:36:21 Applying values
2019/03/28 08:36:21 Apply values: 172.26.0.19
2019/03/28 08:36:21 Outputing file
2019/03/28 08:36:21 Using filename of offline_results.offline_import.nessus
2019/03/28 08:36:21 Writing offline_results.offline_import.nessus
2019/03/28 08:36:21 Done
test$
```
