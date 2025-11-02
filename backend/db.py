import requests
import json
from urllib.parse import urljoin
from .config import SUPABASE_URL, SUPABASE_KEY


# Simple helper functions to interact with Supabase PostgREST endpoints
# Note: you can also install supabase-py and use the client; here we keep
# dependency minimal and use REST API for clarity.


HEADERS = {
'apikey': SUPABASE_KEY,
'Authorization': f'Bearer {SUPABASE_KEY}',
'Content-Type': 'application/json'
}


def supabase_insert(table: str, row: dict):
url = urljoin(SUPABASE_URL.replace('://', '://'), f'/rest/v1/{table}')
resp = requests.post(url, headers=HEADERS, data=json.dumps(row))
resp.raise_for_status()
return resp.json()


def supabase_select(table: str, filters: str = ''):
url = urljoin(SUPABASE_URL.replace('://', '://'), f'/rest/v1/{table}')
if filters:
url = f"{url}?{filters}"
resp = requests.get(url, headers=HEADERS)
resp.raise_for_status()
return resp.json()


def supabase_update(table: str, key_col: str, key_val, updates: dict):
url = urljoin(SUPABASE_URL.replace('://', '://'), f'/rest/v1/{table}')
# simple equality filter
url = f"{url}?{key_col}=eq.{key_val}"
resp = requests.patch(url, headers=HEADERS, data=json.dumps(updates))
resp.raise_for_status()
return resp.json()