# kev_check
Checks for updates to the CISA KEV list compared to the last time that the script was run.

If there are changes then notify to a private Discord channel, as shown below:

<img src="./assets/CISA%20KEV%20notification%202026-01-29.jpg" width="400" />

The Discord notification shows:
- The number of KEVs (previous and current). The count shows in **bold** if it has increased.
- The number of KEVs (previous and current) for a particular vendor that is being tracked. The count shows in **bold** if it has increased.
- Vendor and product names for each new vulnerability in the KEV list.

Optionally checks for updates to the VulnCheck KEV list in the same way (requires free registration to get an API token). Discord notifications for VulnCheck KEV updates will be added in a future update.

## How it works
When the script is run for the first time it creates a local spreadsheet which contains the CISA KEV list data.
This local reference spreadsheet is stored in the input folder for the script.

The reference spreadsheet has three tabs:
- Summary, which stores the high-level details of the last CISA KEV update
- Vulns, which stores the details for each vulnerability in the CISA KEV list
- <vendor_name>, which stores the subset of CISA KEV vulnerabilities that were for a specific vendor

On subsequent runs, the script checks if there are changes to the number of CISA KEV entries compared to the saved sheet.
If the CISA KEV list has changed then a new spreadsheet is created in the output folder during processing.
A notification is sent to a Discord channel if required. This reports on all new vulnerabilities that weren't in the previous saved KEV list.
Finally the local reference spreadsheet in the input folder is replaced with a copy of the new spreadsheet.

## Initial setup

### Data file locations
Create separate input and output folders for the script to use.

For example, **/data/kev_check/in** and **/data/kev_check/out**

### config.yaml
Create a config.yaml file based on the template. *Make sure that config.yaml in specified in your .gitignore file.*

- **in_fn** value is the input file name that will be stored in the input folder created in the previous step.
- **out_path** value is the output folder name that was created in the previous step.
- **vendor_name** value is the name of the vendor that is being tracked. It is also the name of an extra sheet to be created in the output spreadsheet which lists all of the vendor's vulnerabilities. For example "VMware".
- **vendor_list** value is a list including one or more vendorProject values from the CISA KEV data. Note that the list values are case sensitive when filtering the KEV data.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;For example: ["Broadcom", "VMware", "VMware Tanzu", "Vmware"] to collate the subset of KEV vulnerabilities that are for VMware software. The last "Vmware" was needed to support one entry in the VulnCheck data.

#### Optional config.yaml settings for Discord notifications
To send a notification to Discord if there have been changes, setup an appropriate Discord channel and get the webhook URL.

- **notify** value should be changed from *false* to *true*.
- **webhook_url** value should be set to the Discord channel's webhook URL.

#### Optional config.yaml settings to retrieve VulnCheck KEV data
To be able to retrieve the VulnCheck KEV list you will need to register a free account at vulncheck.com and create an API token.

- **use_vc** value should be changed from *false* to *true*.
- **vc_token** value should be set to the API token.

### Running the script
It is recommended to run the script using *uv* for dependency management:
    `uv run python kev.py`

Once the script is working it can be scheduled to run daily (e.g. using crontab).

## Issues
Using this script on a Windows computer initally worked fine, but at one stage *requests* stopped working with an SSL error.

This was resolved with: `uv pip install pip-system-certs`
