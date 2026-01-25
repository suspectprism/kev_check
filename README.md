# kev.py
Download the latest CISA KEV list.
- Download new KEV changes compared to the local version of the list
- Check specifically for vulnerabilities in the KEV list that are for a specific vendor
- Notify to private Discord channel if there is an updated KEV list

## How it works
When the script is run for the first time it creates a local spreadsheet which contains the KEV list data.
This local reference spreadsheet is stored in the input folder for the script.

The reference spreadsheet has three tabs:
- Summary, which stores the high-level details of the last CISA KEV update
- Vulns, which stores the details for each vulnerability in the CISA KEV list
- <vendor_name>, which stores the subset of CISA KEV vulnerabilities that were for a specific vendor

On subsequent runs, the script checks if there are changes to the number of KEV entries compared to the saved sheet.
If the KEV list has changed then a new spreadsheet is created in the output folder during processing.
A notification is sent to a Discord channel if required.
Finally the local reference spreadsheet in the input folder is replaced with a copy of the new spreadsheet.

## Initial setup

### Data file locations
Create separate input and output folders for the script to use.
For example, */data/kev_search/in* and */data/kev_search/out*

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
Run the script using uv for dependency management:
    `uv run python kev.py`

Once the script is working it can be included in a crontab to run it daily.

## Issues
Using this script on a Windows computer initally worked fine, but at one stage *requests* stopped working with an SSL error.

This was resolved with: `uv pip install pip-system-certs`
