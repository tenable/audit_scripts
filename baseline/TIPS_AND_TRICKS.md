# Baseline Tips and Tricks

## Interpreting the Results

The theory behind the baseline scanning is that if you scan a target that is considered a "gold image", run this script with that audit and results, and rescan the target with the new audit, every item should be a PASSED/info result.  But there are a number of factors that will not allow 100% passes on most audits.

Some of the factors include:

- Some checks in the audit are a direct report of a certain result, most notably with WARNING/medium.  If the item in the audit is a report WARNING, it can not change in the baseline audit.  If the audit is a Tenable published audit, these items can generally be identified by having a "NOTE:" in the description that the check was not run. The code inside the audit will have the opening tag being similar to `<report type:"WARNING">`.
- Audits can contain conditional logic that will provide results based on a setting on the target being scanned.  When rescanning the "gold image" system with a baseline audit, the same conditional logic should work, and the results should become a PASSED/info.  But when scanning other hosts, they may take a different conditional path that can provide results that were not present in the original "gold image" results.
- If the output of an audit check includes dynamic data, such as timestamps, a known good value of a baseline will not work. Since the value of a time stamp will change with every execution of the scan matches against the static known good will fail.
- When creating a baseline audit, the original range or regular expression is now abandoned and an absolute value is used in it's place. An example would be a benchmark that accepted a password length of greater than 8 characters, the "gold image" had 7 characters set. The new baseline audit will fail on anything that is not exactly 7 characters. This can be adjusted by adding more known good values, but the end result will always be an audit looking for absolute values.


## Getting the Source Audit

The use of this script requires that there is access to the original audit file used during the scanning of the "gold image".  This is required in order to get the best baseline audit file created based on the results of that scan.

If using a custom audit, having access to the source is not an issue.

If you want to use a Tenable or other third party audit, the original method was to get the source audit from a download site, customize it with the organizations policy values, and treat it as a custom audit when scanning.  The requirement to verify the custom policy values adds overhead and possibilties for missing values, or mis-typing values.

As of March of 2019, a debug option was enabled that allows the source audit to be presented in the Debugging Log Report.  With this, you can run the "gold image" scan using any audit file and enabling Debug Plugin option in the policy.  When the results are done, the source audit can be saved out of the Debugging Log Report.  The only modification that must be done is to remove the first line in the file as it contains a timestamp.


## Custom Audit Content

When creating a custom audit for use as a baseline, the following tips will help get quality results:

* Make the audit relatively flat and use few to no conditionals.  Conditionals may change the results presented on different targets.
* Use items that provide computed results and not static reports.  Static reports will never change results.
* Create results that do not contain time based output.  If a time stamp shows in the results, it is virtually impossible to create a known good value.
* If creating a custom audit item using a command (CMD_EXEC, AUDIT_POWERSHELL), make sure the output is consistently generated.  This tends to mean that all output should be sorted.  If the output comes out in a random order, the baseline will not have a consistent known good to compare with.
