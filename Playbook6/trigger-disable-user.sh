#!/bin/bash
# Playbook 6 - Test Active Response disable-user qua Wazuh API
# Chay tren may host. Cach dung:  ./trigger-disable-user.sh testuser1

USERNAME="${1:-testuser1}"
AGENT_ID="002"

API="https://localhost:55000"
USER="wazuh-wui"
PASS='MyS3cr37P450r.*-'

# Buoc 1: lay token
TOKEN=$(curl -k -s -X POST "$API/security/user/authenticate" -u "$USER:$PASS" \
  | grep -o '"token": "[^"]*' | cut -d'"' -f4)

# Buoc 2: goi AR khoa user (luu y tien to ! va truong arguments chua username)
curl -k -X PUT "$API/active-response?agents_list=$AGENT_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"command\": \"!disable-user\", \"arguments\": [\"$USERNAME\"]}"

echo ""
echo "Kiem tra: sudo passwd -S $USERNAME  (L = locked)"
echo "Mo lai:   sudo usermod -U $USERNAME"
