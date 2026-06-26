#!/bin/bash
# Playbook 5 - Test Active Response qua Wazuh API (cong 55000)
# Chay tren may host (noi co the goi toi Wazuh Manager).
#
# Cach dung:
#   ./trigger-ar.sh 002 linux      # kill browser tren Ubuntu agent (id 002)
#   ./trigger-ar.sh 001 windows    # kill browser tren Windows agent (id 001)

AGENT_ID="${1:-002}"
OS="${2:-linux}"

API="https://localhost:55000"
USER="wazuh-wui"
PASS='MyS3cr37P450r.*-'

if [ "$OS" = "windows" ]; then
  COMMAND="!kill-browser-windows"
else
  COMMAND="!kill-browser-linux"
fi

# Buoc 1: lay token (JWT)
TOKEN=$(curl -k -s -X POST "$API/security/user/authenticate" -u "$USER:$PASS" \
  | grep -o '"token": "[^"]*' | cut -d'"' -f4)

# Buoc 2: gui lenh Active Response (luu y tien to ! truoc ten command)
curl -k -X PUT "$API/active-response?agents_list=$AGENT_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"command\": \"$COMMAND\"}"
