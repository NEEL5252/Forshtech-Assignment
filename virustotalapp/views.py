from .models import *
import requests, os
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
ic(HEADERS)
# Create your views here.
CACHE_TTL = 60 * 60  # 1 hour

def fetch_data_from_vt(endpoint_type: str, endpoint_value: str):
    url = f"{BASE_URL}/{endpoint_type}/{endpoint_value}"
    cache_key = f"vt_{endpoint_type}_{endpoint_value}"
    ic(url)
    # Check if data is in cache
    cached = cache.get(cache_key)
    if cached:
        ic("Cache hit")
        return cached, False
    
    # If not in cache, fetch from VirusTotal DB Records
    try:
        record = VirusTotalReport.objects.get(
            endpoint_type = endpoint_type,
            endpoint_value = endpoint_value
        )
        cache.set(cache_key, record, timeout=CACHE_TTL)
        return record.data, False
    except VirusTotalReport.DoesNotExist:
        ic("Record not found in DB, fetching from VT API")
        
    # If not in cache & DB, fetch from VirusTotal API
    resp = requests.get(url, headers=HEADERS)
    ic(resp)
    if resp.status_code == 200:
        data = resp.json()
        # Save to DB
        VirusTotalReport.objects.create(
            endpoint_type = endpoint_type,
            endpoint_value = endpoint_value
        )
        # Cache the response
        cache.set(cache_key, data, timeout=CACHE_TTL)
        return data, True
    else:
        ic(resp.text)
        raise Exception(f"VT API error: {resp.status_code}, {resp.text}")
        

@api_view(['POST', "GET"])
def get_virustotal_report(request):
    if request.method == "POST":
        data = request.data

        endpoint_type = data.get('endpoint_type', None)
        endpoint_value = data.get('endpoint_value', None)
        
        try:
            if not endpoint_type or not endpoint_value:
                return Response({"error": "endpoint_type and endpoint_value are required."}, status.HTTP_400_BAD_REQUEST)

            data, fetched = fetch_data_from_vt(
                endpoint_type= endpoint_type,
                endpoint_value= endpoint_value
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