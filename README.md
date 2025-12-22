# 1. vcf_vulns.py
Extract relevant VCF vulnerability details from advisories at support.broadcom.com
and save relevant data into a spreadsheet (maybe a database in future).

Script initially processes current Broadcom format security advisories.

Uses config.py. Requires beautifulsoup, requests, pandas and openpyxl

# 2. kev.py
Download the latest CISA KEV list.
- Download new KEV changes compared to the local version of the list.
- Check specifically for Broadcom or VMware as vendor

Uses config.py. Requires requests, openpyxl.
N.B. *requests* stopped working with an SSL error. Resolved with: `uv pip install pip-system-certs`
