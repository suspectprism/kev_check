# kev.py
Download the latest CISA KEV list.
- Download new KEV changes compared to the local version of the list
- Check specifically for Broadcom or VMware as vendor
- Notify to private Discord channel if there is an updated KEV list

Uses config.py. Requires requests, openpyxl, colorama.

N.B. *requests* stopped working with an SSL error. (Windows)

Resolved with: `uv pip install pip-system-certs`
