🧠 VirusTotal Data Pipeline Assignment:
This project is a mini data pipeline built using Django and Django REST Framework (DRF) that integrates with the VirusTotal API to fetch, store, cache, and expose data through REST APIs.

It demonstrates API integration, data persistence, caching, rate limiting, and clean API design — as per the given assignment requirements.

-----------------------------------------------------------
1. 🚀 Features & Functionalities Implemented
🧩 Core Functionalities

1. Django REST Framework (DRF)
Used to build RESTful APIs and provide structured JSON responses.
INSTALLED_APPS = [
    'rest_framework',
]

2. Redis as Cache Database
Used for caching frequently accessed VirusTotal API responses.
Significantly improves performance and reduces redundant VirusTotal API calls.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
    }
}

3. API Rate Limiting (Throttling)
Implemented using DRF Throttle classes to restrict API usage and protect both local API and VirusTotal limits.
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.ScopedRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'fetch_scope': '4/minute',
    }
}

4. VirusTotalReport Model
Custom Django model to persist VirusTotal response data for
 -- domains,
 -- ip_addresses, and
 -- files.

5. Two Main APIs Built
Fetch API – Fetches data dynamically from VirusTotal and exposes it via REST.
Refresh APIs – Re-ingests and updates data manually when needed.

6. Admin Model Registration
Registered VirusTotalReport model in Django Admin to visualize stored data directly from the database.

7. Cache Key Strategy
Cache data is stored with key format:
vt_{endpoint_type}_{endpoint_value}

-----------------------------------------------------------
2. 🧠 2. API Endpoints & Logic
1️⃣ Fetch Data Endpoint
--> URL:
POST /get_virustotal_report/

--> Purpose:
Fetch data from VirusTotal API for public endpoints — domains, ip_addresses, and files.

--> Logic Flow:
1. Check Cache:
When a request comes, the app first checks if data for that endpoint exists in Redis cache.
If yes → return cached data (fastest response).

2. Check Database:
If not found in cache → check the local database (VirusTotalReport model).
If data exists in DB → fetch it and cache it again for future quick access.

3. Fetch from VirusTotal:
If not in cache or DB → make a fresh API call to VirusTotal.
Store the fetched data in both DB and cache.

4. File Handling Logic:
Handling file uploads in VirusTotal works differently compared to domains or IP addresses.

Step 1 — Upload and Get Analysis ID
When a file is uploaded through the API, it doesn’t immediately return a full report.
Instead, VirusTotal returns an analysis ID that represents the scanning process for that file.

Response:
{
  "data": {
    "type": "analysis",
    "id": "analysis_id",
    "links": {
      "self": "https://www.virustotal.com/api/v3/analyses/analysis_id"
    }
  }
}

Step 2 — Poll the Analysis Report
After uploading, the application makes another API request to get the actual analysis result.
Endpoint: 
GET https://www.virustotal.com/api/v3/analyses/{analysis_id}
And then store using file hash.

---
Example Cache Key:
vt_file_87c1b4a... (file hash)

----
2️⃣ Refresh Data Endpoints
These endpoints are used to re-ingest data and refresh existing records.

1. For Domains & IP Addresses
GET /<str:endpoint_type>/<str:endpoint_value>/refresh/
Example: /domains/google.com/refresh/
Re-fetches fresh data from VirusTotal for a given domain or IP.

2. For Files
POST /<str:endpoint_type>/refresh/
Used when re-ingesting data for uploaded files.
Since files don’t have direct endpoint values, this avoids missing-parameter errors.

---
--> Why Two Separate Endpoints?
→ Files require upload and hashing, while domains/IPs have direct identifiers.
Hence, both have separate refresh routes for stability.


----------------------------------
🧪 Example Flow Of the Funcation
Client → /get_virustotal_report/ 
       → Checks Redis Cache 
          - If found → return cached data
          - Else → check Database 
              - If found → cache + return
              - Else → call VirusTotal API 
                    - store in DB + cache + return


----------------------------------
👏 Summary
This project demonstrates:

1. A clean, maintainable data pipeline with caching and persistence.
2. Efficient use of Redis and rate limiting to handle external API constraints.
3. Scalable Django REST design that can be easily extended for additional endpoints.