# Download CISA KEV list from CISA website and extract relevant data
# Save updated KEV data to local Excel spreadsheet
#
# Report any new VMware/Broadcom KEV vulnerabilities found
#
#
# P Dowley   v0.1      22 Dec 2025

import requests
from config import load_config

def main():
    # Open config file
    config_path = "config.yaml"
    config_dict = load_config(config_path)

    # Retrieve KEV list from CISA website
    kev_url = config_dict['kev']['kev_url']
    try:
        response = requests.get(kev_url)
        kev_data = response.json() # Parse the JSON content into a Python dictionary
        print(kev_data)

        kev_in_fn = config_dict['kev']['in_fn']
        kev_out_path = config_dict['kev']['out_path']
    except Exception as e:
        print(f"Error retrieving KEV data from {kev_url}: {e}")
        return

if __name__ == "__main__":
    main()
