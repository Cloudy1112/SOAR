#!/usr/bin/env python3
import sys
import json
import requests
import os
from datetime import datetime

# Đọc đường dẫn file alert.json và URL do Wazuh truyền vào
with open(sys.argv[1], 'r', encoding='utf-8') as alert_file:
	alert_json = json.load(alert_file)

# URL Webhook lấy từ thẻ <hook_url>
hook_url = sys.argv[3]

# Ghi ra file text (pretty JSON) vào cùng thư mục với script, có timestamp
script_dir = os.path.dirname(os.path.abspath(__file__))
timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
out_path = os.path.join(script_dir, f'alert_{timestamp}.txt')
with open(out_path, 'w', encoding='utf-8') as out_file:
	out_file.write(json.dumps(alert_json, indent=2, ensure_ascii=False))

# Gửi toàn bộ JSON thô sang n8n
headers = {'content-type': 'application/json'}
response = requests.post(hook_url, json=alert_json, headers=headers)

sys.exit(0)