#!/usr/bin/env python3
# Playbook 6 - Phan routing can them vao script integration custom-n8n
# Vi tri thuc te: /var/ossec/integrations/custom-n8n (file KHONG co duoi .py)
#
# Day chi la TRICH DOAN phan routing theo rule_id. Tich hop vao script custom-n8n
# da co tu Playbook 1/5. Sau khi sua: chmod 750, chown root:wazuh, restart manager.

# ... (phan doc alert phia tren giu nguyen) ...

rule_id = str(alert.get("rule", {}).get("id", ""))

# ===== ROUTING theo rule_id =====
if rule_id in ("100520", "100530"):
    path = "data-leak"          # Playbook 5
elif rule_id in ("100600", "100610"):
    path = "credential-theft"   # Playbook 6  <-- THEM DONG NAY
else:
    path = "wazuh-alert"        # Playbook 1 (mac dinh)

url = f"http://n8n:5678/webhook/{path}"

# ... (phan gui POST request phia duoi giu nguyen) ...
