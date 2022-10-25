# audit_scripts
Scripts to help work with configuration audit files.

## baseline/create_baseline_audit.py

Python script that will read .audit file and .nessus file and create a new baseline audit based on known good values.

## variables/replace_variables.py

Python script that will replace the variable names in an audit file with thier default values.

## structure/view_audit_structure.py

Python script to visualize the structure of the audit file, most notably the conditional logic of the audit file.

## offline_to_sc/offline_to_sc.py

Python script to take the properties from a .nessus file and place them in a 2nd .nessus file to allow it to be imported into Tenable.sc.

## parse_wrapper/audit_parse.py

Python script that wraps around executing `nasl` and a compliance plugin to parse audit files and output to JSON or other information.

## cli_scanning

Collection of instructions and Python script to execute CLI scans on a local Nessus scanner, or in Tenable.io via the API.

## nessus_convert/nessus_convert.py

Python script that converts a `.nessus` export to CSV or JSON.

## db_audit_migrate/db_audit_migrate.py

Python script that converts an audit file from the Database plugin to a format supported by the new database specific plugins.
