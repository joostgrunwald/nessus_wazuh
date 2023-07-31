import json
import requests  
import time
import csv  
from collections import defaultdict  
from io import StringIO  

# Function to get the scan ID by scan name  
def get_scan_id(scans, scan_name):  
    for scan in scans:  
        if scan['name'] == scan_name:  
            return scan['id']  
    return None  
  
url_base = "https://localhost:8834"  
headers = {  
    "X-ApiKeys": f"accessKey={accesshere}; secretKey={secrethere}",  
    "Content-Type": "application/json",  
}  
  
# Get scans  
response = requests.get(f"{url_base}/scans", headers=headers, verify=False)  
  
if response.status_code == 200:  
    print("Successfully connected to Nessus instance.")  
    scans = response.json()['scans']  
    scan_id = get_scan_id(scans, 'internal daily scan')  
  
    if scan_id:  
        # Prepare request data for exporting the scan report  
        data = {  
            "format": "csv",  
            "reportContents": {  
                "hostSections": {  
                    "scan_information": True,  
                    "host_information": True  
                },  
                "vulnerabilitySections": {  
                    "synopsis": True,  
                    "description": True,  
                    "see_also": True,  
                    "solution": True,  
                    "risk_factor": True,  
                    "cvss3_base_score": True,  
                    "cvss3_temporal_score": True,  
                    "cvss_base_score": True,  
                    "cvss_temporal_score": True,  
                    "stig_severity": True,  
                    "references": True,  
                    "exploitable_with": True,  
                    "plugin_output": True,  
                    "plugin_information": True  
                }  
            }  
        }  
          
        # Export the scan report  
        response = requests.post(f"{url_base}/scans/{scan_id}/export", headers=headers, json=data, verify=False)  
          
        if response.status_code == 200:
            print("Successfully exported the scan report.")  
            export_data = response.json()  
            token = export_data['token']  
            file_id = export_data['file']  
  
            # Check the export status  
            timeout = 10 * 60  # 10 minutes in seconds  
            interval = 5  # 5 seconds  
            elapsed_time = 0  
  
            while elapsed_time < timeout:  
                response = requests.get(f"{url_base}/scans/{scan_id}/export/{file_id}/status", headers=headers, verify=False)  
                  
                if response.status_code == 200:  
                    status = response.json()['status']  
                    if status == "ready":  
                        print("The scan report is ready to download.")  
                        break  
                    else:  
                        print(f"Current status: {status}. Waiting for 5 seconds...")  
                else:  
                    print(f"Failed to get the export status. Status code: {response.status_code}")  
                    break  
                  
                time.sleep(interval)  
                elapsed_time += interval  
  
            if elapsed_time >= timeout:  
                print("Timed out waiting for the scan report to be ready.")
            else:
 # Download the scan report  
                response = requests.get(f"{url_base}/scans/{scan_id}/export/{file_id}/download", headers=headers, verify=False)  
                  
                if response.status_code == 200:  
                    print("Successfully downloaded the scan report.")  
                      
                    # Save the report as a CSV file  
                    with open("scan_report.csv", "wb") as f:  
                        f.write(response.content)  
                    print("Scan report saved as 'scan_report.csv'.") 

                    # conversion to json
                    reader = csv.DictReader(StringIO(response.content.decode('utf-8')))
                    previous_output = None 

                    with open("/var/ossec/logs/active-responses.log", "a") as active_response_log:
                        for row in reader:  
                            json_output = {}
                            host = row['Host']  
                            json_output['nessus_host']=host
                            port = row['Port']  
                            json_output['nessus_port']=port
                            json_output['nessus_plugin_id']=row['Plugin ID']
                            json_output['nessus_cve']=row['CVE']
                            json_output['nessus_cvss_v2.0_base_score']=row['CVSS v2.0 Base Score']
                            json_output['nessus_risk']=row['Risk']
                            json_output['nessus_protocol']=row['Protocol']
                            json_output['nessus_name']=row['Name']
                            json_output['nessus_synopsis']=row['Synopsis']
                            json_output['nessus_description']=row['Description']
                            json_output['nessus_solution']=row['Solution']
                            json_output['nessus_see_also']=row['See Also']
                            json_output['nessus_plugin_output']=row['Plugin Output']
                            # if not risk 'None'
                            if row['Risk'] != 'None':
                                # if description, host, port, name and plugin output are  not same as in previous
                                if previous_output != None:
                                    if row['Description'] == previous_output['nessus_description'] and row['Host'] == previous_output['nessus_host'] and row['Port'] == previous_output['nessus_port'] and row['Name'] == previous_output['nessus_name'] and row['Plugin Output'] == previous_output['nessus_plugin_output']:
                                        previous_output = json_output
                                    else:
                                        active_response_log.write(json.dumps(json_output))
                                        active_response_log.write("\n") 
                                        previous_output = json_output
                                else:
                                    active_response_log.write(json.dumps(json_output))
                                    active_response_log.write("\n") 
                                    previous_output = json_output
                            else:
                                previous_output = json_output
 
                else:  
                    print(f"Failed to download the scan report. Status code: {response.status_code}")   
        else:  
            print(f"Failed to export the scan report. Status code: {response.status_code}")  


    else:  
        print("Scan 'internal daily scan' not found.")  
else:  
    print(f"Failed to connect to Nessus instance. Status code: {response.status_code}")  

