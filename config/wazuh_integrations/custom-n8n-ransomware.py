#!/usr/bin/env python3
import sys
import json
import time
import urllib.request
import urllib.error
import os
import base64
from datetime import datetime

# ------------------- CẤU HÌNH -------------------
DEDUP_WINDOW = 300
CACHE_FILE = "/var/ossec/logs/process_cache.json"
LOG_FILE = "/var/ossec/logs/integrations.log"

# Thông tin kết nối Indexer API
INDEXER_URL = "https://192.168.1.250:9200"   # Địa chỉ indexer
INDEXER_USER = "admin"                       # Tài khoản
INDEXER_PASS = "SecretPassword"              # Mật khẩu

# ------------------- HÀM TIỆN ÍCH -------------------
def write_log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} {msg}\n")

def safe_get(obj, *keys, default=None):
    for key in keys:
        try:
            obj = obj[key]
        except (KeyError, TypeError):
            return default
    return obj

def load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        write_log(f"Error loading cache: {str(e)}")
        return {}

def save_cache(cache):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        write_log(f"Error saving cache: {str(e)}")

def clean_cache(cache, max_age=3600):
    now = time.time()
    to_remove = [k for k, v in cache.items() if now - v.get("timestamp", 0) > max_age]
    for k in to_remove:
        del cache[k]
    return cache

# ------------------- GỌI INDEXER API LẤY HASH -------------------
def query_indexer_for_hash(file_path, agent_id):
    """
    Tìm sự kiện có image hoặc parentImage khớp với file_path,
    trả về SHA256 (chuỗi) hoặc None.
    """
    query = {
        "query": {
            "bool": {
                "should": [
                    {"match": {"data.win.eventdata.image": file_name}},
                    {"match": {"data.win.eventdata.parentImage": file_name}}
                ],
                "minimum_should_match": 1,
                "filter": [
                    {"term": {"agent.id": agent_id}},
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ]
            }
        },
        "size": 1,
        "sort": [{"@timestamp": "desc"}]
    }

    url = f"{INDEXER_URL}/wazuh-alerts-*/_search"
    data = json.dumps(query).encode("utf-8")
    
    # Basic Auth header
    credentials = f"{INDEXER_USER}:{INDEXER_PASS}"
    encoded_auth = base64.b64encode(credentials.encode()).decode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {encoded_auth}"
    }

    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=10) as response:
            resp_data = json.loads(response.read().decode())
            hits = resp_data.get("hits", {}).get("hits", [])
            if hits:
                source = hits[0].get("_source", {})
                hashes_str = safe_get(source, "data", "win", "eventdata", "hashes")
                if hashes_str:
                    for part in hashes_str.split(","):
                        if part.startswith("SHA256="):
                            return part.split("=", 1)[1]
                # Fallback: nếu không có hashes trong eventdata, thử syscheck
                sha256 = safe_get(source, "syscheck", "sha256_after")
                if sha256:
                    return sha256
    except Exception as e:
        write_log(f"Error querying indexer: {str(e)}")
    return None

# ------------------- TRÍCH XUẤT DỮ LIỆU -------------------
def extract_agent_info(alert_data):
    agent = alert_data.get("agent", {})
    return {
        "id": agent.get("id", "unknown"),
        "name": agent.get("name", "unknown"),
        "ip": agent.get("ip", "unknown")
    }

def extract_process_details(alert_data):
    eventdata = safe_get(alert_data, "data", "win", "eventdata", default={})
    if not eventdata:
        return None

    return {
        "process": {
            "image": eventdata.get("image", ""),
            "guid": eventdata.get("processGuid", ""),
            "pid": eventdata.get("processId", ""),
            "commandLine": eventdata.get("commandLine", ""),
            "hashes": eventdata.get("hashes", ""),
            "integrityLevel": eventdata.get("integrityLevel", ""),
            "user": eventdata.get("user", ""),
            "logonGuid": eventdata.get("logonGuid", ""),
            "logonId": eventdata.get("logonId", ""),
            "terminalSessionId": eventdata.get("terminalSessionId", ""),
            "currentDirectory": eventdata.get("currentDirectory", ""),
        },
        "parent": {
            "image": eventdata.get("parentImage", ""),
            "guid": eventdata.get("parentProcessGuid", ""),
            "pid": eventdata.get("parentProcessId", ""),
            "commandLine": eventdata.get("parentCommandLine", ""),
            "user": eventdata.get("parentUser", ""),
        },
        "utcTime": eventdata.get("utcTime", ""),
        "originalFileName": eventdata.get("originalFileName", ""),
        "description": eventdata.get("description", ""),
        "company": eventdata.get("company", ""),
        "fileVersion": eventdata.get("fileVersion", ""),
        "product": eventdata.get("product", "")
    }

def extract_rule_info(alert_data):
    rule = alert_data.get("rule", {})
    return {
        "id": rule.get("id", ""),
        "level": rule.get("level", 0),
        "description": rule.get("description", ""),
        "mitre_id": rule.get("mitre", {}).get("id", [])
    }

def extract_full_log(alert_data):
    return alert_data.get("full_log", "")

# ------------------- XÂY DỰNG PAYLOAD -------------------
def build_payload(alert_data, process_details, agent_info, rule_info, full_log, parent_hash=None):
    cache_key = f"{agent_info['id']}_{process_details['parent']['guid']}_{process_details['process']['guid']}"
    payload = {
        "source": "wazuh_process",
        "timestamp": alert_data.get("timestamp", ""),
        "@timestamp": alert_data.get("@timestamp", ""),
        "agent": agent_info,
        "rule": rule_info,
        "parent": process_details["parent"],
        "process": process_details["process"],
        "utcTime": process_details["utcTime"],
        "originalFileName": process_details["originalFileName"],
        "description": process_details["description"],
        "company": process_details["company"],
        "fileVersion": process_details["fileVersion"],
        "product": process_details["product"],
        "full_log": full_log,
        "cache_key": cache_key
    }
    if parent_hash:
        payload["parent_hash"] = parent_hash
    return payload

# ------------------- XỬ LÝ CACHE & GỬI -------------------
def is_duplicate(cache, cache_key, now, dedup_window):
    if cache_key in cache:
        last_time = cache[cache_key].get("timestamp", 0)
        if now - last_time < dedup_window:
            return True
    return False

def update_cache(cache, cache_key, now, process_details, agent_info, rule_info):
    cache[cache_key] = {
        "timestamp": now,
        "agent_id": agent_info["id"],
        "agent_name": agent_info["name"],
        "parent_image": process_details["parent"]["image"],
        "parent_guid": process_details["parent"]["guid"],
        "process_image": process_details["process"]["image"],
        "process_guid": process_details["process"]["guid"],
        "rule_id": rule_info["id"],
        "rule_level": rule_info["level"]
    }
    save_cache(cache)

# ------------------- HÀM CHÍNH -------------------
def process_alert(alert_file_path, api_key, hook_url):
    try:
        with open(alert_file_path, 'r') as f:
            alert_data = json.load(f)
    except Exception as e:
        write_log(f"Error reading alert file: {str(e)}")
        return

    agent_info = extract_agent_info(alert_data)
    process_details = extract_process_details(alert_data)
    rule_info = extract_rule_info(alert_data)
    full_log = extract_full_log(alert_data)

    if not process_details or not process_details["process"].get("image"):
        write_log("Skipping non-process-creation alert")
        return

    # Lấy hash của parent nếu có parentImage
    parent_hash = None
    parent_image = process_details["parent"].get("image")
    if parent_image:
        write_log(f"Querying hash for parent: {parent_image}")
        parent_hash = query_indexer_for_hash(parent_image, agent_info["id"])
        if parent_hash:
            write_log(f"Found parent hash: {parent_hash}")
        else:
            write_log(f"Parent hash not found for {parent_image}")

    cache_key = f"{agent_info['id']}_{process_details['parent']['guid']}_{process_details['process']['guid']}"
    cache = load_cache()
    cache = clean_cache(cache, max_age=3600)
    now = time.time()

    if is_duplicate(cache, cache_key, now, DEDUP_WINDOW):
        write_log(f"Duplicate suppressed: {cache_key}")
        return

    update_cache(cache, cache_key, now, process_details, agent_info, rule_info)

    payload = build_payload(alert_data, process_details, agent_info, rule_info, full_log, parent_hash)
    data = json.dumps(payload).encode("utf-8")

    try:
        req = urllib.request.Request(
            hook_url,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            body = response.read().decode()
            write_log(f"Sent alert (rule {rule_info['id']}) to n8n. Status: {status}")
            if status == 200:
                write_log(f"Success: {body[:200]}")
            else:
                write_log(f"Failed: {status} - {body}")
    except Exception as e:
        write_log(f"Error sending to n8n: {str(e)}")

# ------------------- ĐIỂM VÀO -------------------
if __name__ == "__main__":
    if len(sys.argv) < 4:
        write_log("ERROR: Missing arguments. Expected: <alert_file> <api_key> <hook_url>")
        sys.exit(1)

    alert_file_path = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 else ""
    hook_url = sys.argv[3] if len(sys.argv) > 3 else ""

    if not hook_url:
        write_log("ERROR: hook_url is empty")
        sys.exit(1)

    process_alert(alert_file_path, api_key, hook_url)