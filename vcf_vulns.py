# Collect VCF vulnerability details from advisories at support.broadcom.com
# and save relevant data into a spreadsheet, maybe a database in future.
#
#
# P Dowley   v0.1      17 Dec 2025

import requests
from bs4 import BeautifulSoup
import re
import pandas as pd

def process_brcm_advisory(advisory_soup):
	cvss_pattern = r'[- ]+' # Regex pattern to split CVSS scores on hyphens and spaces (one or more times)
	cve_pattern = r'[, ]+' # Regex pattern to split CVEs on commas and spaces (one or more times)

	# Extract details from the page title
	page_title = advisory_soup.find('p', class_='ecx-page-title-default').text.strip()
	title_split = page_title.split(":", 1)

	vmsa = title_split[0].strip() # VMSA identifier

	title_remainder = title_split[1].strip()
	index = title_remainder.find("(")
	if index != -1:
		advisory_title = title_remainder[:index].strip() # Advisory title
	else:
		advisory_title = title_remainder.strip()

	cards = advisory_soup.find_all('div', class_='card-body')

	for card in cards:
		rows = card.find_all('div', class_='row')
		for row in rows:
			cells = row.find_all('div', class_='col-4')
			for cell in cells:
				sol_label = cell.find('label', class_='edit-solution-labels').text.strip()
				sol_text = cell.find('p', class_='edit-solution-text').text.strip()

				if sol_label == "Last Updated":
					upd_date = sol_text
				elif sol_label == "Initial Publication Date":
					pub_date = sol_text
				elif sol_label == "Severity":
					severity = sol_text
				elif sol_label == "CVSS Base Score":
					cvss_score = re.split(cvss_pattern, sol_text)
				elif sol_label == "Affected CVE":
					cve_ids = re.split(cve_pattern, sol_text)

	single_cols = advisory_soup.find_all('div', class_='columnLayout single')

	for col in single_cols:
		affected_prods = []

		prod_lines = col.find_all('li')
		for prod_line in prod_lines:
			affected_prods.append(prod_line.text.strip())

	tables = advisory_soup.find_all('tbody')[1:] # Skip the first table which is not relevant

	for table in tables:
		row_list = []
		table_rows = table.find_all('tr')

		for tr in table_rows:
			cell_list = []
			tds = tr.find_all('td')

			for td in tds:
				cell_list.append(td.text.strip())
			
			row_list.append(cell_list)
		
		header = row_list[0] # First row as header
		df = pd.DataFrame(row_list[1:], columns=header) # Remaining rows as data
		print(df)

	print(vmsa, advisory_title, pub_date, upd_date, severity, cvss_score, cve_ids, affected_prods)

def main():
	# Fetch a sample VCF advisory page
	advisory_url = 'https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/36149'
	response = requests.get(advisory_url)
	advisory_content = response.text

	advisory_soup = BeautifulSoup(advisory_content, 'html.parser')

	process_brcm_advisory(advisory_soup)

if __name__ == "__main__":
    main()