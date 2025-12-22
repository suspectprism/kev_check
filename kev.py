# Download CISA KEV list from CISA website and extract relevant data
# Save updated KEV data to local Excel spreadsheet
#
# Show if any new VMware/Broadcom KEV vulnerabilities found
#
#
# P Dowley   v0.1      23 Dec 2025

import requests
import sys
from pathlib import Path
import openpyxl
from datetime import date
import shutil
from colorama import Fore, Style
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
    latest_count = kev_data.get("count", "")

    # Get the existing catalog version and date released from the summary sheet of the local workbook
    saved_catalog_version = None
    saved_date_released = None
    saved_count = None
    vmw_count = None

    for row in ws.iter_rows(min_row=1, values_only=True):
        if row[0] == "Catalog Version":
            saved_catalog_version = row[1]
        elif row[0] == "Date Released":
            saved_date_released = row[1]
        elif row[0] == "Count of Vulnerabilities":
            saved_count = row[1]
        elif row[0] == "Count of VMware/BRCM vulns":
            vmw_count = row[1]

    print(f" Saved KEV catalog version: {saved_catalog_version}, date released: {saved_date_released}, count: {saved_count}")

    # Compare catalog versions and dates to determine if KEV list has been updated
    if latest_catalog_version != saved_catalog_version or latest_date_released != saved_date_released:
        print(f"Latest KEV catalog version: {Fore.GREEN}{latest_catalog_version}{Style.RESET_ALL}, date released: {Fore.GREEN}{latest_date_released}{Style.RESET_ALL}, count: {Fore.YELLOW}{latest_count}{Style.RESET_ALL}")
        return True, vmw_count
    else:
        print(f"Latest KEV catalog version: {latest_catalog_version}, date released: {latest_date_released}, count: {latest_count}")
        return False, vmw_count

def save_kev_to_excel(kev_data, kev_in_fn, kev_out_path):
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
    summary_ws.append(["Count of VMware/BRCM vulns", 0])  # Placeholder for VMware/Broadcom vuln count

    # Set column widths for better readability
    summary_ws.column_dimensions['A'].width = 25
    summary_ws.column_dimensions['B'].width = 40

    #Set cells B1 - B5 to bold text
    for row in summary_ws['B1:B5']:
        for cell in row:
            cell.font = openpyxl.styles.Font(bold=True)

    #Set left alignment for the Count cells
    summary_ws['B4'].alignment = openpyxl.styles.Alignment(horizontal='left')
    summary_ws['B5'].alignment = openpyxl.styles.Alignment(horizontal='left')

    # Write vulnerabilities information
    vulns_ws = wb.create_sheet(title="Vulns", index=1)
    # Write header row
    headers = ["CVE ID", "Vendor", "Product", "Vulnerability Name", "Date Added", "Short Description", "Reqd Action", "Due Date", "Ransomware Campaign"]
    vulns_ws.append(headers)

    # Set header row to bold text
    for cell in vulns_ws[1]:
        cell.font = openpyxl.styles.Font(bold=True)

    # Set column widths for better readability
    col_widths = [15, 15, 20, 40, 10, 40, 15, 10, 20]

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

    # Create a separate sheet for Broadcom/VMware vulnerabilities
    vmw_vulns_ws = wb.copy_worksheet(vulns_ws)
    vmw_vulns_ws.title = "VMware"
    vmw_vulns_ws.index = 2

    # Remove non-VMware/Broadcom entries from the VMware sheet
    for row in range(vmw_vulns_ws.max_row, 1, -1):
        vendor_cell = vmw_vulns_ws.cell(row=row, column=2)  # Vendor is in the second column
        if "VMware" not in vendor_cell.value and "Broadcom" not in vendor_cell.value:
            vmw_vulns_ws.delete_rows(row)

    # Apply autofilter to the VMware sheet
    vmw_vulns_ws.auto_filter.ref = vmw_vulns_ws.dimensions

    # Add the count of VMware/Broadcom entries to the Summary sheet
    vmw_count = vmw_vulns_ws.max_row - 1
    summary_ws['B5'].value = vmw_count
    print(f"Latest VMware count: {Fore.YELLOW}{vmw_count}{Style.RESET_ALL}")

    # Save the workbook to the specified file
    today_str = date.today().isoformat()
    out_fn = Path(kev_out_path) / f"CISA_KEV_{today_str}.xlsx"

    wb.save(out_fn)
    print(f"KEV data saved to {out_fn}")

    # Copy the new KEV file to the input file path for future comparisons
    shutil.copy(out_fn, kev_in_fn)

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
    kev_out_path = config_dict['kev']['out_path']

    if kev_in_path.is_file():   # A saved KEV file exists

        # Check if the KEV list has been updated since last run.
        kev_updated, vmw_count = check_kev_updates(kev_data, kev_in_path)
        if kev_updated:
            # The KEV list has been updated so we need to save the new KEV data
            print(f" Saved VMware count: {vmw_count}")
            save_kev_to_excel(kev_data, kev_in_fn, kev_out_path)
        else:
            print("No changes to KEV list.")

    else:
        # We don't have a previously saved KEV file so we need to save one
        print("Saving KEV data to local Excel spreadsheet...")
        save_kev_to_excel(kev_data, kev_in_fn, kev_out_path)

if __name__ == "__main__":
    main()
