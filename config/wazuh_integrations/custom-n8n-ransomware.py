#!/usr/bin/env python3

import sys
import json
import re
import time
import urllib.request
import urllib.error

def main():
    # Đọc toàn bộ dữ liệu đầu vào từ Wazuh
    data = json.load(sys.stdin)
    
   
    
    # Gửi cảnh báo đến n8n
    try:
        requests.post(webhook_url, json=data, timeout=5)
    except Exception as e:
        sys.stderr.write(f"Error sending to n8n: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        write_log("ERROR: Missing arguments. Usage: custom-n8n-brute-force.py alert_file api_key hook_url")
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3]

    process_alert(alert_file, api_key, hook_url)