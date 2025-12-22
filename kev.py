# Download CISA KEV list from CISA website and extract relevant data
# Save updated KEV data to local Excel spreadsheet
#
# Report any new VMware/Broadcom KEV vulnerabilities found
#
#
# P Dowley   v0.1      22 Dec 2025

import requests
import sys
from pathlib import Path
import openpyxl
from datetime import date
import shutil
from config import load_config

def get_kev_data(kev_url):
    '''Fetch KEV data from the CISA website'''
    try:
        response = requests.get(kev_url)
        response.raise_for_status()  # Raise an error for bad status codes
        kev_data = response.json()  # Parse the JSON content into a Python dictionary
        return kev_data
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving KEV data from {kev_url}: {e}")
        sys.exit(1)  # Exit on error with a non-zero status

def check_kev_updates(kev_data, kev_in_path):
    '''Check if there are any new KEV vulnerabilities since the last saved KEV file'''
    # Load existing KEV data from local Excel file
    wb = openpyxl.load_workbook(kev_in_path)
    ws = wb["Summary"]  # Open the summary sheet to compare header info from KEV data

    # Get the catalog version and date released from the new KEV data on the CISA website
    latest_catalog_version = kev_data.get("catalogVersion", "")
    latest_date_released = kev_data.get("dateReleased", "")

    # Get the existing catalog version and date released from the summary sheet of the local workbook
    saved_catalog_version = None
    saved_date_released = None

    for row in ws.iter_rows(min_row=1, values_only=True):
        if row[0] == "Catalog Version":
            saved_catalog_version = row[1]
        elif row[0] == "Date Released":
            saved_date_released = row[1]

    print(f" Saved KEV catalog version: {saved_catalog_version}, date released: {saved_date_released}")
    print(f"Latest KEV catalog version: {latest_catalog_version}, date released: {latest_date_released}")

    # Compare catalog versions and dates to determine if KEV list has been updated
    if latest_catalog_version != saved_catalog_version or latest_date_released != saved_date_released:
        return True
    else:
        return False

def save_kev_to_excel(kev_data, out_fn):
    '''Save KEV data to an Excel spreadsheet'''

    # Mapping of KEV header names to more user-friendly names, for the summary sheet
    name_dict = {
        "title": "Title",
        "catalogVersion": "Catalog Version",
        "dateReleased": "Date Released",
        "count": "Count of Vulnerabilities"
    }

    # Remove the vulnerabilities list from the main dictionary for separate processing
    vulns_list = kev_data.pop("vulnerabilities")

    wb = openpyxl.Workbook()
    
    # Write summary information to the default sheet
    summary_ws = wb.active
    summary_ws.title = "Summary"
    for key, value in kev_data.items():
        name = name_dict[key] if key in name_dict else key
        summary_ws.append([name, value])

    # Set column widths for better readability
    summary_ws.column_dimensions['A'].width = 20
    summary_ws.column_dimensions['B'].width = 40

    #Set cells B1 - B4 to bold text
    for row in summary_ws['B1:B4']:
        for cell in row:
            cell.font = openpyxl.styles.Font(bold=True)

    #Set left alignment for the Count cell
    summary_ws['B4'].alignment = openpyxl.styles.Alignment(horizontal='left')

    # Write vulnerabilities information
    vulns_ws = wb.create_sheet(title="Vulns", index=1)
    # Write header row
    headers = ["CVE ID", "Vendor", "Product", "Vulnerability Name", "Date Added", "Short Description", "Reqd Action", "Due Date", "Ransomware Campaign"]
    vulns_ws.append(headers)

    # Set header row to bold text
    for cell in vulns_ws[1]:
        cell.font = openpyxl.styles.Font(bold=True)

    # Set column widths for better readability
    col_widths = [15, 15, 20, 40, 10, 40, 15, 10, 15]

    for i, width in enumerate(col_widths, start=1):
        vulns_ws.column_dimensions[openpyxl.utils.get_column_letter(i)].width = width

    # Write KEV entries
    for item in vulns_list:
        cve_id = item.get("cveID", "")
        vendor = item.get("vendorProject", "")
        product = item.get("product", "")
        vuln_name = item.get("vulnerabilityName", "")
        date_added = item.get("dateAdded", "")
        short_desc = item.get("shortDescription", "")
        reqd_action = item.get("requiredAction", "")
        due_date = item.get("dueDate", "")
        ransomware_campaign = item.get("knownRansomwareCampaignUse", False)

        row = [cve_id, vendor, product, vuln_name, date_added, short_desc, reqd_action, due_date, ransomware_campaign]
        vulns_ws.append(row)

    # Apply autofilter to the vulnerabilities sheet
    vulns_ws.auto_filter.ref = vulns_ws.dimensions

    # Save the workbook to the specified file
    wb.save(out_fn)
    print(f"KEV data saved to {out_fn}")

def main():
    # Open config file
    config_path = "config.yaml"
    config_dict = load_config(config_path)

    # Retrieve KEV list from CISA website
    kev_url = config_dict['kev']['kev_url']
    kev_data = get_kev_data(kev_url)

    # Retrieve local saved KEV spreadsheet if it exists
    kev_in_fn = config_dict['kev']['in_fn']
    kev_in_path = Path(kev_in_fn)

    kev_updated = False   # Default is that KEV list has not been updated
    if kev_in_path.is_file():
        # A saved KEV file exists.
        file_exists = True

        # Check if the KEV list has been updated since last run.
        kev_updated = check_kev_updates(kev_data, kev_in_path)
        print(f"KEV list updated: {kev_updated}")
    else:
        file_exists = False

    if not file_exists or kev_updated:
        # If we don't have a saved KEV file then we need to save the KEV data; or
        # if the KEV list has been updated then we need to save the new KEV data.
        print("Saving updated KEV data to local Excel spreadsheet...")

        # Save KEV data to local Excel spreadsheet
        kev_out_path = config_dict['kev']['out_path']
        today_str = date.today().isoformat()
        kev_out_fn = Path(kev_out_path) / f"CISA_KEV_{today_str}.xlsx"
        save_kev_to_excel(kev_data, kev_out_fn)

        # Copy the new KEV file to the input file path for future comparisons
        shutil.copy(kev_out_fn, kev_in_fn)

if __name__ == "__main__":
    main()
