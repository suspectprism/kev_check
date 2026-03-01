# Check for updates to CISA KEV (Known Exploited Vulnerabilities) list
#
# v0.1 Download CISA KEV list from CISA website and extract relevant data
#      Save updated KEV data to local Excel spreadsheet
#
# v0.2 If KEV list is updated then notify to a private Discord channel
#
# v0.3 Support use of a generic (instead of hard-coded) vendor when checking for vendor vulns
#      Improved formatting of Discord notification message
#      List new vulnerabilities in Discord message
#
# P Dowley   v0.3.1      1 Mar 2026

import requests
from discord_webhook import DiscordWebhook, DiscordEmbed
import sys
from pathlib import Path
import openpyxl
from openpyxl import styles
from openpyxl import utils
from datetime import date, datetime
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

def notify_to_discord(saved_summary_dict, kev_data, vulns_list, vend_name, vend_count, webhook_url):
    '''Send message to private Discord channel via webhook to notify of KEV updates'''

    # Convert string with ISO format date to a datetime
    saved_release_dt = datetime.fromisoformat(saved_summary_dict['dateReleased'].replace("Z", "+00:00"))
    saved_release_str = f"{saved_release_dt:%Y-%m-%d}"  # Reformat this as a simple date string for Discord message

    # Convert string with ISO format date to a datetime
    kev_release_dt = datetime.fromisoformat(kev_data['dateReleased'].replace("Z", "+00:00"))
    kev_release_str = f"{kev_release_dt:%Y-%m-%d}"  # Reformat this as a simple date string for Discord message

    prev_str = (
        f"Date: {saved_release_str}, "
        f"count: {saved_summary_dict['count']},\n "
        f"{vend_name}: {saved_summary_dict['vendCount']}"
    )

    if vend_count == saved_summary_dict['vendCount']:
        # Vendor vuln count has not changed
        vend_count_bold = ""
    else:
        # Vendor vuln count has changed so highlight this in bold
        vend_count_bold = "**"

    latest_str = (
        f"Date: {kev_release_str}, "
        f"count: **{kev_data['count']}**,\n"
        f"{vend_name}: {vend_count_bold}{vend_count}{vend_count_bold}"
    )

    webhook = DiscordWebhook(url=webhook_url)

    embed = DiscordEmbed(title="CISA KEV List updated",
                         color='03b2f8')  # Blue colour for embed

    embed.add_embed_field(name="Previous KEV",
                         value=prev_str, inline=False)
    
    embed.add_embed_field(name="Latest KEV",
                          value=latest_str, inline=False)

    # New vulnerability details
    num_new_vulns = int(kev_data['count']) - int(saved_summary_dict['count'])
    vulns_str = ""
    counter = 0
    while counter < num_new_vulns:
        vuln = vulns_list[counter]
        vuln_str = vuln['cveID'] + " *" +vuln['vendorProject'] + "* - " + vuln['product']  # Asterisks around vendor name for italics in Discord markdown
        if counter == 0:
            vulns_str = vuln_str
        else:
            vulns_str = vulns_str + "\n\n" + vuln_str
        counter += 1

    embed.add_embed_field(name=f"New vulnerabilities",
                          value=vulns_str, inline=False)

    webhook.add_embed(embed)

    # Submit message to the Discord webhook URL
    response = webhook.execute()

    if response.status_code == 200: # Discord returns 200 for successful webhook posts
        print("Notification to Discord sent successfully.")
    else:
        print(f"Failed to send notification. Status code: {response.status_code}")
        print(response.content)

    return

def check_kev_updates(kev_header, vulns_list, kev_in_path, notify_discord, webhook_url, vendor_list, vendor_name):
    '''Check if there are any new KEV vulnerabilities since the last saved KEV file'''

    # Convert string with ISO format date to a datetime
    kev_release_dt = datetime.fromisoformat(kev_header['dateReleased'].replace("Z", "+00:00"))
    kev_release_str = f"{kev_release_dt:%Y-%m-%d %H:%M:%S}"  # Reformat this as a more readable string for console output

    # Load existing KEV data from local Excel file
    wb = openpyxl.load_workbook(kev_in_path)
    ws = wb["Summary"]  # Open the summary sheet to compare header info from KEV data

    # Mapping of spreadsheet header names to KEV header names
    vend_header = "Count of " + vendor_name + " vulns"
    name_dict = {
        "Title": "title",
        "Catalog Version": "catalogVersion",
        "Date Released": "dateReleased",
        "Count of Vulnerabilities": "count",
        vend_header: "vendCount"
    }
    # Get the existing catalog version and date released from the summary sheet of the local workbook
    saved_summary_dict = {}

    for row in ws.iter_rows(min_row=1, values_only=True):
        key = row[0]
        value = row[1]

        if key is not None:
            saved_summary_dict[name_dict[key]] = value

    # Convert string with ISO format date to a datetime
    saved_release_dt = datetime.fromisoformat(saved_summary_dict['dateReleased'].replace("Z", "+00:00"))
    saved_release_str = f"{saved_release_dt:%Y-%m-%d %H:%M:%S}"  # Reformat this as a more readable string for console output

    vend_count = 0
    for vuln in vulns_list:
        if vuln["vendorProject"] in vendor_list:
            vend_count += 1

    print(f" Saved KEV catalog version: {saved_summary_dict['catalogVersion']}, "
          f"date: {saved_release_str}, "
          f"count: {saved_summary_dict['count']}, "
          f"{vendor_name}: {saved_summary_dict['vendCount']}")

    # Compare catalog versions and dates to determine if KEV list has been updated
    if kev_header["catalogVersion"] != saved_summary_dict['catalogVersion'] or kev_header["dateReleased"] != saved_summary_dict["dateReleased"]:
        if saved_summary_dict['vendCount'] == vend_count:
            # Highlight the overall KEV count in yellow because it has changed
            print(f"Latest KEV catalog version: {Fore.GREEN}{kev_header['catalogVersion']}{Style.RESET_ALL}, "
                  f"date: {Fore.GREEN}{kev_release_str}{Style.RESET_ALL}, "
                  f"count: {Fore.YELLOW}{kev_header['count']}{Style.RESET_ALL}, "
                  f"{vendor_name}: {vend_count}")
        else:
            # Vendor vuln count has changed so highlight this too
            print(f"Latest KEV catalog version: {Fore.GREEN}{kev_header['catalogVersion']}{Style.RESET_ALL}, "
                  f"date: {Fore.GREEN}{kev_release_str}{Style.RESET_ALL}, "
                  f"count: {Fore.YELLOW}{kev_header['count']}{Style.RESET_ALL}, "
                  f"{vendor_name}: {Fore.RED}{vend_count}{Style.RESET_ALL}")

        if notify_discord:
            notify_to_discord(saved_summary_dict, kev_header, vulns_list, vendor_name, vend_count, webhook_url)
        else:
            print("Notification to Discord is not required.")

        return True
    else:
        print(f"Latest KEV catalog version: {kev_header["catalogVersion"]}, "
              f"date: {kev_release_str}, "
              f"count: {kev_header["count"]}, "
              f"{vendor_name}: {vend_count}")
        
        return False

def save_kev_to_excel(kev_header, vulns_list, vendor_list, vendor_name, kev_in_fn, kev_out_path):
    '''Save KEV data to an Excel spreadsheet'''

    # Mapping of KEV header names to more user-friendly names, for the summary sheet
    name_dict: dict = {
        "title": "Title",
        "catalogVersion": "Catalog Version",
        "dateReleased": "Date Released",
        "count": "Count of Vulnerabilities"
    }

    wb = openpyxl.Workbook()
    
    # Write summary information to the default sheet
    summary_ws = wb.active
    summary_ws.title = "Summary"

    vend_header:str = "Count of " + vendor_name + " vulns"
    for key, value in kev_header.items():
        name = name_dict[key] if key in name_dict else key
        summary_ws.append([name, value])
    summary_ws.append([vend_header, 0])  # Placeholder for vendor vuln count

    # Set column widths for better readability
    summary_ws.column_dimensions['A'].width = 25
    summary_ws.column_dimensions['B'].width = 40

    #Set cells B1 - B5 to bold text
    for row in summary_ws['B1:B5']:
        for cell in row:
            cell.font = styles.Font(bold=True)

    #Set left alignment for the Count cells
    summary_ws['B4'].alignment = styles.Alignment(horizontal='left')
    summary_ws['B5'].alignment = styles.Alignment(horizontal='left')

    # Write vulnerabilities information
    vulns_ws = wb.create_sheet(title="Vulns", index=1)
    # Write header row
    headers = ["CVE ID", "Vendor", "Product", "Vulnerability Name", "Date Added", "Short Description", "Reqd Action", "Due Date", "Ransomware Campaign"]
    vulns_ws.append(headers)

    # Set header row to bold text
    for cell in vulns_ws[1]:
        cell.font = styles.Font(bold=True)

    # Set column widths for better readability
    col_widths = [15, 15, 20, 40, 10, 40, 15, 10, 20]

    for i, width in enumerate(col_widths, start=1):
        vulns_ws.column_dimensions[utils.get_column_letter(i)].width = width

    # Write KEV entries
    for item in vulns_list:
        cve_id: str = item.get("cveID", "")
        vendor: str = item.get("vendorProject", "")
        product: str = item.get("product", "")
        vuln_name: str = item.get("vulnerabilityName", "")
        date_added = item.get("dateAdded", "")
        short_desc:str = item.get("shortDescription", "")
        reqd_action:str = item.get("requiredAction", "")
        due_date = item.get("dueDate", "")
        ransomware_campaign = item.get("knownRansomwareCampaignUse", False)

        row:list = [cve_id, vendor, product, vuln_name, date_added, short_desc, reqd_action, due_date, ransomware_campaign]
        vulns_ws.append(row)

    # Apply autofilter to the vulnerabilities sheet
    vulns_ws.auto_filter.ref = vulns_ws.dimensions

    # Create a separate sheet for vendor vulnerabilities
    vend_vulns_ws = wb.copy_worksheet(vulns_ws)
    vend_vulns_ws.title = vendor_name
    vend_vulns_ws.index = 2

    # Remove non-vendor entries from the vendor sheet
    for row_ctr in range(vend_vulns_ws.max_row, 1, -1):
        vendor_cell = vend_vulns_ws.cell(row=row_ctr, column=2)  # Vendor is in the second column
        if vendor_cell.value not in vendor_list:
            vend_vulns_ws.delete_rows(row_ctr)

    # Apply autofilter to the vendor sheet
    vend_vulns_ws.auto_filter.ref = vend_vulns_ws.dimensions

    # Add the count of vendor entries to the Summary sheet
    vend_count = vend_vulns_ws.max_row - 1
    summary_ws['B5'].value = vend_count
    print(f"Latest {vendor_name} count: {Fore.YELLOW}{vend_count}{Style.RESET_ALL}")

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
    kev_url:str = config_dict['kev']['kev_url']
    kev_data = get_kev_data(kev_url)

    # Remove the vulnerabilities list from the main dictionary for separate processing
    vulns_list = kev_data.pop("vulnerabilities")
    kev_header = kev_data

    # Path for saved KEV spreadsheet if it exists
    kev_in_fn:str = config_dict['kev']['in_fn']
    kev_in_path = Path(kev_in_fn)
    # Path for output KEV spreadsheet
    kev_out_path:str = config_dict['kev']['out_path']

    # Vendor references from config
    vend_list:list = config_dict['kev']['vendor_list']
    vend_name:str = config_dict['kev']['vendor_name']

    if kev_in_path.is_file():   # A saved KEV file exists

        # Check if the KEV list has been updated since last run, and notify via Discord webhook if changed
        kev_updated = check_kev_updates(kev_header, vulns_list, kev_in_path, config_dict['kev']['notify'], config_dict['kev']['webhook_url'], vend_list, vend_name)
        if kev_updated:
            # The KEV list has been updated so we need to save the new KEV data
            save_kev_to_excel(kev_header, vulns_list, vend_list, vend_name, kev_in_fn, kev_out_path)
        else:
            print("No changes to KEV list.")

    else:
        # We don't have a previously saved KEV file so we need to save one
        print("Saving KEV data to local Excel spreadsheet...")
        save_kev_to_excel(kev_header, vulns_list, vend_list, vend_name, kev_in_fn, kev_out_path)

if __name__ == "__main__":
    main()
