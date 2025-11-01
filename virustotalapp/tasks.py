from .models import *
from django.core.cache import cache
import requests, os, hashlib, json, sys
from celery import shared_task
from dotenv import load_dotenv
import pandas as pd
from icecream import ic
from django.utils import timezone
load_dotenv()

API_KEY = os.getenv("API_KEY")
BASE_URL = os.getenv("BASE_URL")

HEADERS = {
    "accept": "application/json", "x-apikey": API_KEY
}

@shared_task
def refresh_virus_total_data():
    sys.stdout.write("Starting VirusTotal Data Refresh Task...\n")

    # Fetch all VirusTotalReport records from the database
    virust_total_reports = VirusTotalReport.objects.all()
    df = pd.DataFrame(virust_total_reports.values())
    df['cache_url_wo_files'] = "vt_" + df['endpoint_type'] + "_" + df['endpoint_value']

    # For the endpoints without file data
    sys.stdout.write("Refreshing data for endpoints without file data...\n")
    for index, values in df.iterrows():
        # Get necessary details
        id = values['id']
        cache_url = values['cache_url_wo_files']
        endpoint_type = values['endpoint_type']
        endpoint_value = values['endpoint_value']
        file_scan = values['file_scan']

        # Clear cache
        cached = cache.get(cache_url)
        if cached:
            cache.delete(cache_url)


        # Fetch latest data from virustotalapi
        if endpoint_type == "files":
            # Refreshing file data
            url = f"{BASE_URL}/files"
            with open("media/" + file_scan, 'rb') as f:
                files = {'file': (os.path.basename("media/" + file_scan), f.read())}
                resp = requests.post(url, headers=HEADERS, files=files)
            if resp.status_code == 200:
                data = resp.json()
                analysis_link = data.get("data", {}).get("links", {}).get("self", "")
                file_analysis_resp = requests.get(analysis_link, headers=HEADERS)
                if file_analysis_resp.status_code == 200:
                    data = file_analysis_resp.json()

                    # -------- optimization pending
                    update_data = VirusTotalReport.objects.get(id = id)
                    update_data.full_data = data
                    update_data.last_updated_at =  timezone.now()
                    update_data.save()
                else:
                    sys.stdout.write(f"Error refreshing data for file ID {id}: {file_analysis_resp.status_code}, {file_analysis_resp.text}\n")
            else:
                sys.stdout.write(f"Error refreshing data for file ID {id}: {resp.status_code}, {resp.text}\n")
        else:
            # Refreshing non-file data
            url = f"{BASE_URL}/{endpoint_type}/{endpoint_value}"
            resp = requests.get(url, headers=HEADERS)
            if resp.status_code == 200:
                data = resp.json()

                # -------- optimization pending
                update_data = VirusTotalReport.objects.get(id = id)
                update_data.full_data = data
                update_data.last_updated_at =  timezone.now()
                update_data.save()

            else:
                sys.stdout.write(f"Error refreshing data for file ID {id}: {resp.status_code}, {resp.text}\n")
            
    sys.stdout.write("Data refresh for endpoints without file data completed.\n")
    return "VirusTotal Data Refreshed Successfully"