import requests
import time
import os
from dotenv import load_dotenv

# def scan_file(file: object)->bool:
#     files_url = "https://www.virustotal.com/api/v3/files"
#     files = {"file":file}
#     files_headers = {
#         "accept": "application/json",
#         "x-apikey": 'e8754012f767d2597fde2871984db1786856adbdf8ceb3fbd176661c61b32900'
#     }
#     response = requests.post(files_url,files=files,headers=files_headers)
#     if response.status_code==200:
#         responsedata=response.json()
#         fileid=responsedata['data']['id']
#     else:
#         return "Error uploading file.",'UploadError'
#
#     analysis_url = "https://www.virustotal.com/api/v3/analyses/" + fileid
#     analysis_headers={
#         "accept": "application/json",
#         "x-apikey": 'e8754012f767d2597fde2871984db1786856adbdf8ceb3fbd176661c61b32900'}
#     analyseresponse = requests.get(analysis_url,headers=analysis_headers)
#     # attempts = 1
#     # while attempts < 120 and analyseresponse.status_code == 200 and analyseresponse.json()["data"]["attributes"]["status"] in ['queued', 'in-progress']:
#     #     time.sleep(1)
#     #     analyseresponse = requests.get(analysis_url,headers=analysis_headers)
#     #     print('1',analyseresponse.json())
#     #     attempts += 1
#     #     # if attempts more than 30 just timeout
#     #     if attempts >= 120:
#     #         return 'Timeout'
#     if analyseresponse.status_code==200:
#         analysis_response = analyseresponse.json()
#         print('2',analysis_response)
#         positive = analysis_response["data"]["attributes"]["stats"]["suspicious"]
#         malicious = analysis_response["data"]["attributes"]["stats"]["malicious"]
#         if positive == 0 and malicious == 0:
#             return "The file is safe. No antivirus engines detected any threats.", 'Safe'
#         elif positive > 0 or malicious>0:
#             return f"The file is potentially unsafe.", 'Unsafe'
#         else:
#             return "Error occurred during file scanning.", 'Scan'
#     else:
#         return "Error uploading file.", 'UploadError'

load_dotenv()
def scan_file(file: object) -> bool:
    # upload endpoint
    files_url = "https://www.virustotal.com/api/v3/files"

    # specify post payload
    files = {"file": (file.filename, file, file.content_type)}
    files_headers = {
        "accept": "application/json",
        "x-apikey": os.getenv('VIRUSTOTAL_PDF_KEY')
    }

    # post
    files_response = requests.post(files_url, files=files, headers=files_headers)


    # get response
    if files_response.status_code == 200:
        # if response is ok
        files_response_data = files_response.json()
        # get the id from json response
        analysis_id = files_response_data["data"]["id"]

    else:
        return 'UploadError'

    # analysis endpoint with file id
    analysis_url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id

    # specify headers
    analysis_headers = {
        "accept": "application/json",
        "x-apikey": os.getenv('VIRUSTOTAL_PDF_KEY')
    }

    # post
    analysis_response = requests.get(analysis_url, headers=analysis_headers)

    # declare attempts count
    attempts = 1

    # retry getting analysis response for max 120 times in 2 minutes if virustotal slow like snorlax
    while attempts < 120 and analysis_response.status_code == 200 and analysis_response.json()["data"]["attributes"]["status"] in ['queued', 'in-progress']:
        time.sleep(1)
        analysis_response = requests.get(analysis_url, headers=analysis_headers)
        attempts += 1
        # if attempts more than 30 just timeout
        if attempts >= 30:
            return f'File timed out.','Timeout'

    # get response
    if analysis_response.status_code == 200:
        # if response is ok
        analysis_response_data = analysis_response.json()
        amogusus = analysis_response_data["data"]["attributes"]["stats"]["suspicious"]
        malicious = analysis_response_data["data"]["attributes"]["stats"]["malicious"]

        # if got sussy
        if amogusus > 0 or malicious > 0:
            return f"The file is potentially unsafe.", 'Unsafe'

        # if no sussy
        elif amogusus == 0 and malicious == 0:
            file.seek(0)
            return "The file is safe. No antivirus engines detected any threats.", 'Safe'

        else:
            return "Error occurred during file scanning.", 'Scan'

    else:
        # handle errors
        return "Error occurred during file scanning.", 'Scan'


# def scan_file(file):
#     api_key = 'e8754012f767d2597fde2871984db1786856adbdf8ceb3fbd176661c61b32900'
#
#     # Endpoint for scanning files
#     url = 'https://www.virustotal.com/vtapi/v2/file/report'
#     # API parameters
#     params = {'apikey': api_key, 'resource': ''}
#
#     try:
#         # Upload the file for scanning
#         upload_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
#         upload_params = {'apikey': 'e8754012f767d2597fde2871984db1786856adbdf8ceb3fbd176661c61b32900'}
#         upload_response = requests.post(upload_url, files={'file': file}, params=upload_params)
#         upload_result = upload_response.json()
#
#         # Check the response for errors
#         if 'response_code' in upload_result and upload_result['response_code'] == 1:
#             resource = upload_result['resource']
#             params['resource'] = resource
#
#             # Retrieve the scan report for the file
#             response = requests.get(url, params=params)
#             result = response.json()
#
#             # Check the response for errors
#             if 'response_code' in result and result['response_code'] == 1:
#                 positives = result['positives']
#                 total = result['total']
#
#                 if positives == 0:
#                     return "The file is safe. No antivirus engines detected any threats.",'Safe'
#                 else:
#                     return f"The file is potentially unsafe. Detected {positives}/{total} antivirus engines.",'Unsafe'
#
#             else:
#                 return "Error occurred during report retrieval.",'Report'
#
#         else:
#             return "Error occurred during file scanning.",'Scan'
#
#     except IOError:
#         return "Error uploading file.",'UploadError'

# Example usage
# api_key = 'e8754012f767d2597fde2871984db1786856adbdf8ceb3fbd176661c61b32900'  # Replace with your VirusTotal API key
