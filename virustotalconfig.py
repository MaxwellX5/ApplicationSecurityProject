import os

import requests
import time
from flask import flash, redirect, url_for
from dotenv import load_dotenv
load_dotenv()
def analyse_pfp(image_file: object) -> bool:
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "accept": "application/json",
        "x-apikey": os.getenv("VIRUSTOTAL_API_KEY")
    }
    files = {"file": (image_file.filename, image_file, image_file.content_type)}
    idresponse = requests.post(url, files=files, headers=headers)

    if idresponse.status_code == 200:
        idresponse = idresponse.json()
        link = idresponse['data']['links']['self']
        print(link)
    else:
        print("Error uploading file")
        return False
    response = requests.get(link, headers=headers)
    tries = 0
    while tries <= 30 and response.status_code == 200 and response.json()["data"]["attributes"]["status"] != "completed":
        print("Try ", tries+1)
        tries += 1
        time.sleep(2)
        response = requests.get(link, headers=headers)
    if response.status_code == 200:
        virus_detected = False
        data = response.json()
        results = data['data']['attributes']['results']
        if len(results.items()) == 0:
            print("API on cooldown")
            image_file.seek(0)
            return True
        for engine, result in results.items():
            print(result["category"])
            if result['category'] == 'malicious' or result['category'] == 'suspicious':
                virus_detected = True
                break
        if virus_detected:
            print("Virus detected")
            return True
        else:
            image_file.seek(0)
            print("No Virus detected")
            return False
    else:
        print("Error getting analysis")
        return False
