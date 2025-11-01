from .models import *
from django.core.cache import cache
import requests, os, hashlib, json, sys
from celery import shared_task
from dotenv import load_dotenv
import pandas as pd
from icecream import ic
load_dotenv()

API_KEY = os.getenv("API_KEY")
BASE_URL = os.getenv("BASE_URL")

HEADERS = {
    "accept": "application/json", "x-apikey": API_KEY
}

@shared_task
def refresh_virus_total_data():
    sys.stdout.write("Starting VirusTotal Data Refresh Task...\n")
    endpoint_types_list = [
        "domains",
        "ip_addresses"
    ]

    without_file_data = VirusTotalReport.objects.filter(endpoint_type__in = endpoint_types_list).values()
    file_data = VirusTotalReport.objects.filter(endpoint_type = "files").values()
    
    wo_file_df = pd.DataFrame(without_file_data)
    wo_file_df['cache_url_wo_files'] = "vt_" + wo_file_df['endpoint_type'] + "_" + wo_file_df['endpoint_value']

    for index, values in wo_file_df.iterrows():
        id = values['id']
        cache_url = values['cache_url_wo_files']
        endpoint_type = values['endpoint_type']
        endpoint_value = values['endpoint_value']
        cached = cache.get(cache_url)
        if cached:
            cache.delete(cache_url)

        # Fetch latest data from virustotalapi
        url = f"{BASE_URL}/{endpoint_type}/{endpoint_value}"
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code == 200:
            data = resp.json()

            # -------- optimization pending
            update_data = VirusTotalReport.objects.get(id = id)
            update_data.full_data = data
            update_data.save()

        else:
            pass
    
    return "VirusTotal Data Refreshed Successfully"