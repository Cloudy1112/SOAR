#!/usr/bin/env python3
import sys
import json
import time
import urllib.request
import urllib.error
import os
from datetime import datetime

# ------------------- CẤU HÌNH -------------------
DEDUP_WINDOW = 300          # 5 phút, không gửi lại cùng một sự kiện trong khoảng này
CACHE_FILE = "/var/ossec/logs/fim_cache.json"
LOG_FILE = "/var/ossec/logs/integrations.log"

# ------------------- HÀM TIỆN ÍCH -------------------
def write_log(msg):
    """Ghi log vào file integrations.log"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} {msg}\n")

def safe_get(obj, *keys, default=None):
    """Truy cập an toàn vào nested dict"""
    for key in keys:
        try:
            obj = obj[key]
        except (KeyError, TypeError):
            return default
    return obj

def load_cache():
    """Đọc cache từ file JSON"""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        write_log(f"Error loading cache: {str(e)}")
        return {}

def save_cache(cache):
    """Ghi cache vào file JSON"""
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        write_log(f"Error saving cache: {str(e)}")

def clean_cache(cache, max_age=3600):
    """Xóa các entry cũ hơn max_age (giây)"""
    now = time.time()
    to_remove = [k for k, v in cache.items() if now - v.get("timestamp", 0) > max_age]
    for k in to_remove:
        del cache[k]
    return cache

# ------------------- HÀM TRÍCH XUẤT DỮ LIỆU CHO RANSOMWARE -------------------
def extract_agent_info(alert_data):
    """Lấy thông tin agent"""
    agent = alert_data.get("agent", {})
    return {
        "id": agent.get("id", "unknown"),
        "name": agent.get("name", "unknown"),
        "ip": agent.get("ip", "unknown")
    }

def extract_fim_details(alert_data):
    """Trích xuất các trường FIM whodata cần thiết"""
    syscheck = alert_data.get("syscheck", {})
    audit = syscheck.get("audit", {})
    process = audit.get("process", {})
    user = audit.get("user", {})

    return {
        "event_type": syscheck.get("event", "unknown"),      # added, modified, deleted
        "file_path": syscheck.get("path", ""),
        "mode": syscheck.get("mode", ""),                    # whodata / realtime
        "process_name": process.get("name", ""),
        "process_id": process.get("id", ""),
        "user_name": user.get("name", ""),
        "user_id": user.get("id", ""),
        "sha256_before": syscheck.get("sha256_before", ""),
        "sha256_after": syscheck.get("sha256_after", ""),
        "md5_before": syscheck.get("md5_before", ""),
        "md5_after": syscheck.get("md5_after", ""),
        "diff": syscheck.get("diff", ""),                    # nội dung thay đổi (nếu report_changes=yes)
        "changed_attrs": syscheck.get("changed_attributes", []),
        "size_before": syscheck.get("size_before", 0),
        "size_after": syscheck.get("size_after", 0)
    }

def extract_rule_info(alert_data):
    """Trích xuất thông tin rule và MITRE"""
    rule = alert_data.get("rule", {})
    mitre = rule.get("mitre", {})
    return {
        "id": rule.get("id", ""),
        "level": rule.get("level", 0),
        "description": rule.get("description", ""),
        "mitre_id": mitre.get("id", []),
        "mitre_technique": mitre.get("technique", []),
        "mitre_tactic": mitre.get("tactic", [])
    }

def extract_full_log(alert_data):
    """Lấy full_log (chứa chi tiết thay đổi)"""
    return alert_data.get("full_log", "")

# ------------------- HÀM XÂY DỰNG PAYLOAD CHO n8n -------------------
def build_payload(alert_data, fim_details, agent_info, rule_info, full_log):
    """Tạo payload JSON gửi đến webhook n8n"""
    # Tạo một cache key độc nhất (agent + file_path + event_type + user)
    cache_key = f"{agent_info['id']}_{fim_details['file_path']}_{fim_details['event_type']}_{fim_details['user_name']}"
    return {
        "source": "wazuh_fim",
        "timestamp": alert_data.get("timestamp"),
        "agent": agent_info,
        "rule": rule_info,
        "fim": {
            "event_type": fim_details["event_type"],
            "file_path": fim_details["file_path"],
            "mode": fim_details["mode"],
            "process": {
                "name": fim_details["process_name"],
                "pid": fim_details["process_id"]
            },
            "user": {
                "name": fim_details["user_name"],
                "sid": fim_details["user_id"]
            },
            "hash": {
                "sha256_before": fim_details["sha256_before"],
                "sha256_after": fim_details["sha256_after"],
                "md5_before": fim_details["md5_before"],
                "md5_after": fim_details["md5_after"]
            },
            "diff": fim_details["diff"],
            "changed_attributes": fim_details["changed_attrs"],
            "size_before": fim_details["size_before"],
            "size_after": fim_details["size_after"]
        },
        "full_log": full_log,
        "cache_key": cache_key   # hỗ trợ debug cache
    }

# ------------------- XỬ LÝ CACHE -------------------
def is_duplicate(cache, cache_key, now, dedup_window):
    """Kiểm tra xem sự kiện đã được gửi trong dedup_window chưa"""
    if cache_key in cache:
        last_time = cache[cache_key].get("timestamp", 0)
        if now - last_time < dedup_window:
            return True
    return False

def update_cache(cache, cache_key, now, fim_details, agent_info, rule_info):
    """Cập nhật cache với thông tin sự kiện mới"""
    cache[cache_key] = {
        "timestamp": now,
        "agent_id": agent_info["id"],
        "agent_name": agent_info["name"],
        "file_path": fim_details["file_path"],
        "event_type": fim_details["event_type"],
        "process_name": fim_details["process_name"],
        "user_name": fim_details["user_name"],
        "rule_id": rule_info["id"],
        "rule_level": rule_info["level"]
    }
    save_cache(cache)

# ------------------- HÀM CHÍNH (THEO ĐÚNG CHỮ KÝ YÊU CẦU) -------------------
def process_alert(alert_file_path, api_key, hook_url):
    """
    Đọc file alert, trích xuất dữ liệu FIM, kiểm tra cache và gửi đến n8n.
    """
    try:
        with open(alert_file_path, 'r') as f:
            alert_data = json.load(f)
    except Exception as e:
        write_log(f"Error reading alert file {alert_file_path}: {str(e)}")
        return

    # 1. Trích xuất dữ liệu từ alert
    agent_info = extract_agent_info(alert_data)
    fim_details = extract_fim_details(alert_data)
    rule_info = extract_rule_info(alert_data)
    full_log = extract_full_log(alert_data)

    # Nếu không phải sự kiện syscheck (phòng hờ)
    if not fim_details["event_type"]:
        write_log("Skipping non-syscheck alert")
        return

    # 2. Tạo cache key duy nhất
    cache_key = f"{agent_info['id']}_{fim_details['file_path']}_{fim_details['event_type']}_{fim_details['user_name']}"

    # 3. Load cache và làm sạch
    cache = load_cache()
    cache = clean_cache(cache, max_age=3600)   # tự động xóa cache quá 1 giờ
    now = time.time()

    # 4. Kiểm tra duplicate
    if is_duplicate(cache, cache_key, now, DEDUP_WINDOW):
        write_log(f"Duplicate suppressed: {cache_key}")
        return

    # 5. Cập nhật cache
    update_cache(cache, cache_key, now, fim_details, agent_info, rule_info)

    # 6. Xây dựng payload
    payload = build_payload(alert_data, fim_details, agent_info, rule_info, full_log)
    data = json.dumps(payload).encode("utf-8")

    # 7. Gửi đến n8n webhook
    try:
        req = urllib.request.Request(
            hook_url,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            body = response.read().decode()
            write_log(f"Sent alert {rule_info['id']} to n8n. Status: {status}")
            if status == 200:
                write_log(f"Success: {body[:200]}")   # log tối đa 200 ký tự
            else:
                write_log(f"Failed: {status} - {body}")
    except urllib.error.HTTPError as e:
        write_log(f"HTTP Error: {e.code} - {e.reason}")
    except urllib.error.URLError as e:
        write_log(f"URL Error: {e.reason}")
    except Exception as e:
        write_log(f"Unexpected error sending to n8n: {str(e)}")

# ------------------- ĐIỂM VÀO CỦA SCRIPT (DÙNG CHO WAZUH INTEGRATION) -------------------
if __name__ == "__main__":
    # Wazuh integrator gọi script với 4 tham số: alert_file, api_key, hook_url, full_alert_file
    if len(sys.argv) < 4:
        write_log("ERROR: Missing arguments. Expected: <alert_file> <api_key> <hook_url> [full_alert_file]")
        sys.exit(1)

    alert_file_path = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 else ""
    hook_url = sys.argv[3] if len(sys.argv) > 3 else ""

    if not hook_url:
        write_log("ERROR: hook_url is empty")
        sys.exit(1)

    process_alert(alert_file_path, api_key, hook_url)