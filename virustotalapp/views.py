from .models import *
import requests, os, hashlib

from django.conf import settings
from django.core.cache import cache
from dotenv import load_dotenv
load_dotenv()
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from icecream import ic
VT_API_KEY = os.getenv("API_KEY")
BASE_URL = os.getenv("BASE_URL")

HEADERS = {"accept": "application/json", "x-apikey": VT_API_KEY}

# Create your views here.
CACHE_TTL = 60 * 60  # 1 hour


def compute_file_hash(file):
    hash_sha256 = hashlib.sha256()
    for chunk in iter(lambda: file.read(4096), b""):
        hash_sha256.update(chunk)
    file.seek(0)  # reset cursor for reuse
    return hash_sha256.hexdigest()

def fetch_data_from_vt(endpoint_type: str, endpoint_value: str, file: str = None):

    if file is None:
        url = f"{BASE_URL}/{endpoint_type}/{endpoint_value}"
    else:
        endpoint_value = compute_file_hash(file)
        url = f"{BASE_URL}/files"

    cache_key = f"vt_{endpoint_type}_{endpoint_value}"

    # Check if data is in cache
    cached = cache.get(cache_key)
    if cached:
        return cached, False
    
    # If not in cache, fetch from VirusTotal DB Records
    try:
        
        record = VirusTotalReport.objects.get(
            endpoint_type = endpoint_type,
            endpoint_value = endpoint_value
        )
        cache.set(cache_key, record, timeout=CACHE_TTL)
        return record.full_data, False
    except VirusTotalReport.DoesNotExist:
        ic("Record not found in DB, fetching from VT API")
        
    # If not in cache & DB, fetch from VirusTotal API
    if file:
        files = {'file': (file.name, file.read())}
        resp = requests.post(url, headers=HEADERS, files=files)
    else:
        resp = requests.get(url, headers=HEADERS)
        
    if resp.status_code == 200:
        data = resp.json()
        # Save to DB
        
        if file:
            analysis_link = data.get("data", {}).get("links", {}).get("self", "")
            file_analysis_resp = requests.get(analysis_link, headers=HEADERS)
            if file_analysis_resp.status_code == 200:
                data = file_analysis_resp.json()
            else:
                raise Exception(f"VT API error while fetching file analysis: {file_analysis_resp.status_code}, {file_analysis_resp.text}")

        VirusTotalReport.objects.create(
            endpoint_type = endpoint_type,
            endpoint_value = endpoint_value,
            file_scan = file if file else None,
            full_data = data
        )

        # Cache the response
        cache.set(cache_key, data, timeout=CACHE_TTL)
        return data, True
    else:
        raise Exception(f"VT API error: {resp.status_code}, {resp.text}")
    

@api_view(['POST', "GET"])
def get_virustotal_report(request):
    if request.method == "POST":
        data = request.data
        endpoint_type = data.get('endpoint_type', None)
        endpoint_value = data.get('endpoint_value', None)
        files = request.FILES.get('file', None)

        try:
            if endpoint_type != "files":
                if not endpoint_type or not endpoint_value:
                    return Response({"error": "endpoint_type and endpoint_value are required."}, status.HTTP_400_BAD_REQUEST)

            data, fetched = fetch_data_from_vt(
                endpoint_type= endpoint_type,
                endpoint_value= endpoint_value,
                file= files if files else None
            )
            return Response({
                "source": "VirusTotal API" if fetched else "Cache/DB",
                "data": data,
            }, status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        endpoint_types = [
            "domains",
            "ip_addresses",
            "files"
        ]
        return Response({"endpoint_types": endpoint_types})
    

@api_view(['POST'])
def refresh_data(request, endpoint_type, endpoint_value : str = None):
    data = request.data
    file = request.FILES.get('file', None)
    # Re-ingest the data from VirusTotal API and update DB & Cache
    try:
        if file:
            endpoint_value = compute_file_hash(file)
            
        cache_key = f"vt_{endpoint_type}_{endpoint_value}"
        VirusTotalReport.objects.filter(endpoint_type=endpoint_type, endpoint_value=endpoint_value).delete()
        cache.delete(cache_key)

        data, _ = fetch_data_from_vt(endpoint_type, endpoint_value, file=file if file else None)
        return Response({"status": "refreshed", "data": data})
    
    except Exception as e:
        return Response({"error": str(e)}, status.HTTP_500_INTERNAL_SERVER_ERROR)