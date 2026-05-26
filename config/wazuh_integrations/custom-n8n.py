#!/usr/bin/env python3
import sys
import json
import requests

# Đọc đường dẫn file alert.json và URL do Wazuh truyền vào
alert_file = open(sys.argv[1])
alert_json = json.loads(alert_file.read())
alert_file.close()

# URL Webhook lấy từ thẻ <hook_url>
hook_url = sys.argv[3]

# Gửi toàn bộ JSON thô sang n8n
headers = {'content-type': 'application/json'}
response = requests.post(hook_url, json=alert_json, headers=headers)

sys.exit(0)