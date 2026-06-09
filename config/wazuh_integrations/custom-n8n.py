#!/usr/bin/env python3

import sys
import json
import re
import time
import urllib.request
import urllib.error
from pathlib import Path

LOG_FILE = "/var/ossec/logs/integrations.log"
CACHE_FILE = "/var/ossec/logs/integration_cache.json"
DEDUP_WINDOW = 300  # 5 phút

def write_log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{msg}\n")

def safe_get(dct, *keys, default="N/A"):
    for key in keys:
        if isinstance(dct, dict):
            dct = dct.get(key, {})
        else:
            return default
    return dct if dct != {} else default

def load_cache():
    """Đọc cache từ file JSON, trả về dict rỗng nếu không có."""
    try:
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_cache(cache):
    """Ghi cache ra file JSON (ghi nguyên tử bằng cách tạo file tạm)."""
    tmp_path = CACHE_FILE + ".tmp"
    with open(tmp_path, 'w') as f:
        json.dump(cache, f, indent=2)
    Path(tmp_path).rename(CACHE_FILE)  # atomic trên Linux

def clean_cache(cache, max_age=3600):
    """Xóa các mục cũ hơn max_age (giây) để file không phình to."""
    now = time.time()
    return {k: v for k, v in cache.items() if now - v["timestamp"] < max_age}

def extract_attacker_ip(alert_data):
    # 1. Thử nguồn syslog (SSH Linux)
    srcip = safe_get(alert_data, "data", "srcip", default=None)
    if srcip and srcip != "N/A":
        return srcip
    srcip = safe_get(alert_data, "data", "src_ip", default=None)
    if srcip and srcip != "N/A":
        return srcip

    # 2. Thử Windows event (RDP, SSH Windows) – LẤY ipAddress TRỰC TIẾP
    ip = safe_get(alert_data, "data", "win", "eventdata", "ipAddress", default=None)
    if ip and ip != "N/A" and ip != "-":
        return ip

    # 3. Parse full_log (nếu có)
    full_log = alert_data.get("full_log", "")
    if full_log:
        match = re.search(r'rhost=(\S+)', full_log)
        if match:
            return match.group(1)
        match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', full_log)
        if match:
            return match.group(1)

    # 4. Thử message Windows (fallback)
    msg = safe_get(alert_data, "data", "win", "system", "message", default="")
    if msg and msg != "N/A":
        match = re.search(r'Source Network Address:\s+(\S+)', msg)
        if match and match.group(1) != '-':
            return match.group(1)

    return "unknown"

def extract_target_user(alert_data):
    user = safe_get(alert_data, "data", "win", "eventdata", "targetUserName", default=None)
    if user and user != "N/A":
        return user
    user = safe_get(alert_data, "data", "dstuser", default=None)
    if user and user != "N/A":
        return user
    full_log = alert_data.get("full_log", "")
    if full_log:
        match = re.search(r'Failed password for (invalid user )?(\S+) from', full_log)
        if match:
            return match.group(2)
        match = re.search(r'for user (\S+) from', full_log)
        if match:
            return match.group(1)
    return "unknown"

def extract_process(alert_data):
    proc = safe_get(alert_data, "data", "win", "eventdata", "processName", default=None)
    if proc and proc != "N/A":
        return proc
    proc = safe_get(alert_data, "data", "program_name", default=None)
    if proc and proc != "N/A":
        return proc
    proc = alert_data.get("predecoder", {}).get("program_name")
    if proc:
        return proc
    return "unknown"

def extract_message(alert_data):
    msg = safe_get(alert_data, "data", "win", "system", "message", default=None)
    if msg and msg != "N/A":
        return msg
    msg = alert_data.get("full_log")
    if msg:
        return msg
    return "No message"

def extract_logon_type(alert_data):
    """Lấy mã logon type từ Windows event, nếu có."""
    logon = safe_get(alert_data, "data", "win", "eventdata", "logonType", default=None)
    return logon if logon and logon != "N/A" else "N/A"

def map_protocol(logon_type):
    """Ánh xạ logon type sang tên giao thức thân thiện."""
    mapping = {
        "3": "RDP (Network)",
        "8": "SSH (NetworkCleartext)",
        "10": "RDP (RemoteInteractive)",
        "2": "Interactive (Console)",
    }
    return mapping.get(logon_type, f"Unknown ({logon_type})")

def process_alert(alert_file_path, api_key, hook_url):
    try:
        with open(alert_file_path, 'r') as f:
            alert_data = json.load(f)

        rule = alert_data.get("rule", {})
        agent = alert_data.get("agent", {})
        logon_type = extract_logon_type(alert_data)
        protocol = map_protocol(logon_type) if logon_type != "N/A" else "N/A"

        attacker_ip = extract_attacker_ip(alert_data)

        # ---------- KIỂM TRA CACHE ----------
        cache = load_cache()
        now = time.time()
        cache = clean_cache(cache, max_age=3600)

        # Xác định khóa cache
        if attacker_ip != "unknown":
            cache_key = attacker_ip
        else:
            # Dùng agent_id + target_user + protocol làm khóa dự phòng
            target_user = extract_target_user(alert_data)
            cache_key = f"{agent.get('id')}_{target_user}_{protocol}"

        # Kiểm tra và lưu cache
        if cache_key in cache:
            last_time = cache[cache_key]["timestamp"]
            if now - last_time < DEDUP_WINDOW:
                write_log(f"INFO: Suppressed duplicate alert for key {cache_key} (last sent {now - last_time:.1f}s ago)")
                return

        cache[cache_key] = {
            "timestamp": now,
            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "technique": rule.get("mitre", {}).get("technique", []),
            "attacker_ip": attacker_ip  # giữ lại IP để tham khảo
        }
        save_cache(cache)
        # ---------------------------------------------------------

        # Tạo payload gửi đến n8n
        payload = {
            "source": "wazuh",
            "timestamp": alert_data.get("timestamp"),
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "rule_description": rule.get("description"),
            "agent_name": agent.get("name"),
            "agent_ip": agent.get("ip"),
            "agent_id": agent.get("id"),
            "attacker_ip": attacker_ip,
            "target_user": extract_target_user(alert_data),
            "logon_type": logon_type,          # Mã gốc (3,8,10...)
            "protocol": protocol,              # Tên thân thiện
            "process": extract_process(alert_data),
            "status": safe_get(alert_data, "data", "win", "eventdata", "status", default="N/A"),
            "sub_status": safe_get(alert_data, "data", "win", "eventdata", "subStatus", default="N/A"),
            "workstation": safe_get(alert_data, "data", "win", "eventdata", "workstationName", default="N/A"),
            "message": extract_message(alert_data),
            "mitre": rule.get("mitre", []),
            "full_log": alert_data.get("full_log", "")
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(hook_url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            body = response.read().decode()
            write_log(f"Sent alert {rule.get('id')} to n8n. Status: {status}")
            if status == 200:
                write_log(f"Success: {body}")
            else:
                write_log(f"Failed: {status} - {body}")

    except urllib.error.HTTPError as e:
        write_log(f"HTTP Error: {e.code} - {e.reason}")
    except urllib.error.URLError as e:
        write_log(f"URL Error: {e.reason}")
    except Exception as e:
        write_log(f"Error in integration script: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        write_log("ERROR: Missing arguments. Usage: custom-n8n.py alert_file api_key hook_url")
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3]

    process_alert(alert_file, api_key, hook_url)