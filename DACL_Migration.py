#This script is to migrate DACL from Cisco ACS to Cisco ISE. I have replaced actual IPs and credentials by "x"
import requests
import csv


url = 'https://x.x.x.x:9060/ers/config/downloadableacl'
headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}


with open('ACS_export_to_ISE.csv') as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:

                data = {
  "DownloadableAcl": {
    "name": "EC_VPN_" + row[0],
    "description": "Imported from ACS",
    "dacl": row[1].replace("\\n","\n"),
    "daclType": "IPV4"
  }
}
                print(data)
                r = requests.post(url, auth=('xxx', 'xxx'), verify=False, json=data, headers=headers)