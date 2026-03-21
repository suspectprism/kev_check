# kev_check
Checks for updates to the CISA KEV list compared to the last time that the script was run.

If there are changes then notify to a private Discord channel, as shown below:

<img src="./assets/CISA%20KEV%20notification%202026-01-29.jpg" width="400" />

The Discord notification shows:
- The number of KEVs (previous and current). The count shows in **bold** if it has increased.
- The number of KEVs (previous and current) for a particular vendor that is being tracked. The count shows in **bold** if it has increased.
- Vendor and product names for each new vulnerability in the KEV list.

## How it works
When the script is run for the first time it creates a local spreadsheet which contains the KEV list data.
This local reference spreadsheet is stored in the input folder for the script.

The reference spreadsheet has three tabs:
- Summary, which stores the high-level details of the last CISA KEV update
- Vulns, which stores the details for each vulnerability in the CISA KEV list
- <vendor_name>, which stores the subset of CISA KEV vulnerabilities that were for a specific vendor

On subsequent runs, the script checks if there are changes to the number of KEV entries compared to the saved sheet.
If the KEV list has changed then a new spreadsheet is created in the output folder during processing.
A notification is sent to a Discord channel if required. This reports on all new vulnerabilities that weren't in the previous saved KEV list.
Finally the local reference spreadsheet in the input folder is replaced with a copy of the new spreadsheet.

## Initial setup

### Data file locations
Create separate input and output folders for the script to use.
For example, */data/kev_check/in* and */data/kev_check/out*

### config.yaml
Create a config.yaml file based on the template. (Include config.yaml in your .gitignore file.)
Update the *in_fn* and *out_path* values to match the folder names that were created in the previous step.

Update the *vendor_name* value with the name of the extra sheet to be created in the output spreadsheet. For example "VMware".

Update the *vendor_list* value to be a list including one or more vendorProject values from the CISA KEV data.
For example: ["Broadcom", "VMware", "VMware Tanzu"] to collate the subset of KEV vulnerabilities that are for VMware software.

### Discord notifications
To send a notification to Discord if there have been changes, setup an appropriate Discord channel and get the webhook URL.
Set the channel's webhook URL in the *webhook_url* entry in config.yaml.

Update the *notify* value from *false* to *true*.

### Running the script
It is recommended to run the script using **uv** for dependency management:
    `uv run python kev.py`

Once the script is working it can be scheduled to run daily (e.g. using crontab).

## Issues
Using this script on a Windows computer initally worked fine, but at one stage *requests* stopped working with an SSL error.

This was resolved with: `uv pip install pip-system-certs`
