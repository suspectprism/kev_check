# Download CISA KEV list from CISA website and extract relevant data
# Save updated KEV data to local Excel spreadsheet
#
# If KEV list is updated then notify to a private Discord channel
#
#
# P Dowley   v0.2.1      2 Jan 2026

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

def notify_to_discord(saved_summary_dict, kev_data, vmw_count, webhook_url):
    '''Send message to private Discord channel via webhook to notify of KEV updates'''

    msg_data = {
        "content": f" Saved date: {saved_summary_dict['dateReleased']}, "
          f"count: {saved_summary_dict['count']}, "
          f" VMW/BRCM: {saved_summary_dict['vmwCount']}\n"
          f"Latest date: {kev_data['dateReleased']}, "
          f"count: {kev_data['count']}, "
          f" VMW/BRCM: {vmw_count}"
    }

    # Make a POST request to the Discord webhook URL
    response = requests.post(webhook_url, json= msg_data)

    if response.status_code == 204: # Discord returns 204 / No Content for successful webhook posts
        print("Notification to Discord sent successfully.")
    else:
        print(f"Failed to send notification. Status code: {response.status_code}")
        print(response.content)

    return

def check_kev_updates(kev_header, vulns_list, kev_in_path, webhook_url):
    '''Check if there are any new KEV vulnerabilities since the last saved KEV file'''
    # Load existing KEV data from local Excel file
    wb = openpyxl.load_workbook(kev_in_path)
    ws = wb["Summary"]  # Open the summary sheet to compare header info from KEV data

    # Mapping of spreadsheet header names to KEV header names
    name_dict = {
        "Title": "title",
        "Catalog Version": "catalogVersion",
        "Date Released": "dateReleased",
        "Count of Vulnerabilities": "count",
        "Count of VMware/BRCM vulns": "vmwCount"
    }
    # Get the existing catalog version and date released from the summary sheet of the local workbook
    saved_summary_dict = {}

    for row in ws.iter_rows(min_row=1, values_only=True):
        key = row[0]
        value = row[1]

        if key is not None:
            saved_summary_dict[name_dict[key]] = value

    vmw_count = 0
    for vuln in vulns_list:
        if vuln["vendorProject"] in ["Broadcom", "VMware", "VMware Tanzu"]:
            vmw_count += 1

    print(f" Saved KEV catalog version: {saved_summary_dict['catalogVersion']}, "
          f"date: {saved_summary_dict['dateReleased']}, "
          f"count: {saved_summary_dict['count']}, "
          f"VMW/BRCM: {saved_summary_dict['vmwCount']}")

    # Compare catalog versions and dates to determine if KEV list has been updated
    if kev_header["catalogVersion"] != saved_summary_dict['catalogVersion'] or kev_header["dateReleased"] != saved_summary_dict["dateReleased"]:
        print(f"Latest KEV catalog version: {Fore.GREEN}{kev_header['catalogVersion']}{Style.RESET_ALL}, "
              f"date: {Fore.GREEN}{kev_header['dateReleased']}{Style.RESET_ALL}, "
              f"count: {Fore.YELLOW}{kev_header['count']}{Style.RESET_ALL}, "
              f"VMW/BRCM: {vmw_count}")
        
        notify_to_discord(saved_summary_dict, kev_header, vmw_count, webhook_url)

        return True
    else:
        print(f"Latest KEV catalog version: {kev_header["catalogVersion"]}, "
              f"date: {kev_header["dateReleased"]}, "
              f"count: {kev_header["count"]}, "
              f"VMW/BRCM: {vmw_count}")
        
        return False

def save_kev_to_excel(kev_header, vulns_list, kev_in_fn, kev_out_path):
    '''Save KEV data to an Excel spreadsheet'''

    # Mapping of KEV header names to more user-friendly names, for the summary sheet
    name_dict = {
        "title": "Title",
        "catalogVersion": "Catalog Version",
        "dateReleased": "Date Released",
        "count": "Count of Vulnerabilities"
    }

    wb = openpyxl.Workbook()
    
    # Write summary information to the default sheet
    summary_ws = wb.active
    summary_ws.title = "Summary"
    for key, value in kev_header.items():
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

    # Remove the vulnerabilities list from the main dictionary for separate processing
    vulns_list = kev_data.pop("vulnerabilities")
    kev_header = kev_data

    # Retrieve local saved KEV spreadsheet if it exists
    kev_in_fn = config_dict['kev']['in_fn']
    kev_in_path = Path(kev_in_fn)
    kev_out_path = config_dict['kev']['out_path']

    if kev_in_path.is_file():   # A saved KEV file exists

        # Check if the KEV list has been updated since last run, and notify via Discord webhook if changed
        kev_updated = check_kev_updates(kev_header, vulns_list, kev_in_path, config_dict['kev']['webhook_url'])
        if kev_updated:
            # The KEV list has been updated so we need to save the new KEV data
            save_kev_to_excel(kev_header, vulns_list, kev_in_fn, kev_out_path)
        else:
            print("No changes to KEV list.")

    else:
        # We don't have a previously saved KEV file so we need to save one
        print("Saving KEV data to local Excel spreadsheet...")
        save_kev_to_excel(kev_header, vulns_list, kev_in_fn, kev_out_path)

if __name__ == "__main__":
    main()
