#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import re
import time
import urllib.request
import urllib.error
import hashlib
from pathlib import Path
import fcntl

LOG_FILE = "/var/ossec/logs/integrations.log"
CACHE_DIR = "/var/ossec/logs/batch_cache"
BATCH_WINDOW = 10  # giây, thời gian gom nhóm

def write_log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")

def ensure_cache_dir():
    Path(CACHE_DIR).mkdir(parents=True, exist_ok=True)

def safe_get(dct, *keys, default="N/A"):
    for key in keys:
        if isinstance(dct, dict):
            dct = dct.get(key, {})
        else:
            return default
    return dct if dct != {} else default

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

def decode_proctitle(full_log):
    if not full_log:
        return None, None
    match = re.search(r'proctitle=([0-9a-fA-F]+)', full_log)
    if not match:
        return None, None
    hex_str = match.group(1)
    try:
        raw_bytes = bytes.fromhex(hex_str)
        decoded = raw_bytes.decode('utf-8', errors='replace')
        decoded = decoded.replace('\x00', ' ')
        return hex_str, decoded
    except Exception as e:
        write_log(f"Error decoding proctitle: {e}")
        return hex_str, f"<decode error: {e}>"

def get_batch_key(alert_data):
    """Tạo key duy nhất cho nhóm: agent_id + proctitle_hash (nếu có)"""
    agent_id = alert_data.get("agent", {}).get("id", "unknown")
    full_log = alert_data.get("full_log", "")
    _, decoded = decode_proctitle(full_log)
    if decoded:
        # dùng hash của lệnh để nhóm
        proctitle_hash = hashlib.md5(decoded.encode()).hexdigest()
    else:
        # fallback: dùng rule_id + timestamp gần đúng (không gom nhóm được)
        proctitle_hash = "no_proctitle"
    return f"{agent_id}_{proctitle_hash}"

def load_batch(key):
    """Đọc batch từ file cache"""
    path = Path(CACHE_DIR) / f"{key}.json"
    if not path.exists():
        return None
    try:
        with open(path, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # shared lock
            data = json.load(f)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return data
    except Exception as e:
        write_log(f"Error reading batch {key}: {e}")
        return None

def save_batch(key, data):
    """Ghi batch vào file cache (atomic)"""
    tmp_path = Path(CACHE_DIR) / f"{key}.tmp"
    final_path = Path(CACHE_DIR) / f"{key}.json"
    try:
        with open(tmp_path, 'w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            json.dump(data, f, indent=2)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        tmp_path.rename(final_path)
    except Exception as e:
        write_log(f"Error saving batch {key}: {e}")

def delete_batch(key):
    """Xóa batch sau khi gửi"""
    path = Path(CACHE_DIR) / f"{key}.json"
    try:
        path.unlink(missing_ok=True)
    except Exception as e:
        write_log(f"Error deleting batch {key}: {e}")

def flush_batch(key, hook_url):
    """Gửi batch đi và xóa cache"""
    batch = load_batch(key)
    if not batch:
        return

    # Xây dựng payload tổng hợp
    alert_list = batch.get("alerts", [])
    if not alert_list:
        return

    # Lấy thông tin từ alert đầu tiên
    first = alert_list[0]
    rule_ids = list(set(a.get("rule", {}).get("id") for a in alert_list))
    mitre_all = []
    for a in alert_list:
        m = a.get("rule", {}).get("mitre", {})
        if m:
            mitre_all.append(m)

    # Gom MITRE
    mitre_merged = {
        "id": list(set([i for m in mitre_all for i in m.get("id", [])])),
        "technique": list(set([t for m in mitre_all for t in m.get("technique", [])])),
        "tactic": list(set([t for m in mitre_all for t in m.get("tactic", [])]))
    }

    # Lấy decoded command từ proctitle của alert đầu tiên
    full_log_first = first.get("full_log", "")
    proctitle_hex, decoded_cmd = decode_proctitle(full_log_first)

    payload = {
        "source": "wazuh",
        "timestamp": first.get("timestamp"),
        "agent_name": first.get("agent", {}).get("name"),
        "agent_ip": first.get("agent", {}).get("ip"),
        "agent_id": first.get("agent", {}).get("id"),
        "process": extract_process(first),
        "rule_ids": rule_ids,
        "rule_level": max([a.get("rule", {}).get("level", 0) for a in alert_list]),
        "description": "; ".join(set([a.get("rule", {}).get("description", "") for a in alert_list])),
        "mitre": mitre_merged,
        "message": extract_message(first),  # có thể lấy từ alert đầu
        "proctitle_hex": proctitle_hex,
        "decoded_command": decoded_cmd,
        "full_logs": [a.get("full_log") for a in alert_list],  # giữ nguyên để debug
        "alert_count": len(alert_list)
    }

    # Gửi payload
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(hook_url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            body = response.read().decode()
            write_log(f"Flushed batch {key} (count={len(alert_list)}) to n8n. Status: {status}")
            if status == 200:
                write_log(f"Success: {body[:200]}")
            else:
                write_log(f"Failed: {status} - {body[:200]}")
    except Exception as e:
        write_log(f"Error sending batch {key}: {e}")
    finally:
        delete_batch(key)

def process_alert(alert_file_path, api_key, hook_url):
    try:
        with open(alert_file_path, 'r') as f:
            alert_data = json.load(f)

        # Tạo key batch
        key = get_batch_key(alert_data)
        if key.endswith("no_proctitle"):
            # Không có proctitle, không gom nhóm được, gửi ngay
            write_log(f"No proctitle found, sending immediately for rule {alert_data.get('rule',{}).get('id')}")
            send_single(alert_data, hook_url)
            return

        ensure_cache_dir()
        now = time.time()

        # Đọc batch hiện tại (nếu có)
        batch = load_batch(key)
        if batch is None:
            # Tạo batch mới
            batch = {
                "created_at": now,
                "alerts": [alert_data]
            }
            save_batch(key, batch)
            write_log(f"Created new batch {key} with first alert {alert_data.get('rule',{}).get('id')}")
        else:
            # Kiểm tra nếu batch đã hết hạn (quá BATCH_WINDOW giây)
            if now - batch["created_at"] > BATCH_WINDOW:
                # Flush batch cũ
                flush_batch(key, hook_url)
                # Tạo batch mới
                batch = {
                    "created_at": now,
                    "alerts": [alert_data]
                }
                save_batch(key, batch)
                write_log(f"Flushed old batch and created new {key}")
            else:
                # Thêm alert vào batch hiện tại
                batch["alerts"].append(alert_data)
                save_batch(key, batch)
                write_log(f"Added alert {alert_data.get('rule',{}).get('id')} to batch {key}, count={len(batch['alerts'])}")

        # Lên lịch flush sau BATCH_WINDOW giây (có thể dùng cron hoặc timer, nhưng đơn giản là không gửi ngay)
        # Thay vào đó, mỗi lần có alert mới sẽ kiểm tra và flush nếu đã quá hạn.
        # Để đảm bảo batch được gửi khi không có alert mới, cần một cơ chế ngoài (cron).
        # Ở đây, ta sẽ không gửi ngay, chỉ lưu. Việc gửi sẽ do một tiến trình cron chạy định kỳ,
        # hoặc ta có thể gửi ngay khi batch đạt số lượng tối đa (tùy chọn).
        # Để đơn giản, ta sẽ gửi ngay nếu batch có >= 5 alert (giảm tần suất)
        # Hoặc để chắc chắn, ta sẽ viết thêm một script cron riêng để flush các batch cũ.

        # Tạm thời, nếu số lượng alert >= 3, flush ngay (để không chờ lâu)
        if len(batch["alerts"]) >= 3:
            flush_batch(key, hook_url)

    except Exception as e:
        write_log(f"Error in process_alert: {str(e)}")

def send_single(alert_data, hook_url):
    """Gửi một alert đơn lẻ (khi không có proctitle)"""
    rule = alert_data.get("rule", {})
    agent = alert_data.get("agent", {})
    full_log = alert_data.get("full_log", "")
    proctitle_hex, decoded_cmd = decode_proctitle(full_log)

    payload = {
        "source": "wazuh",
        "timestamp": alert_data.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "agent_id": agent.get("id"),
        "process": extract_process(alert_data),
        "message": extract_message(alert_data),
        "mitre": rule.get("mitre", []),
        "full_log": full_log,
        "proctitle_hex": proctitle_hex,
        "decoded_command": decoded_cmd
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(hook_url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            write_log(f"Sent single alert {rule.get('id')} to n8n. Status: {response.status}")
    except Exception as e:
        write_log(f"Error sending single alert: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        write_log("ERROR: Missing arguments. Usage: custom-n8n.py alert_file api_key hook_url")
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3]

    process_alert(alert_file, api_key, hook_url)