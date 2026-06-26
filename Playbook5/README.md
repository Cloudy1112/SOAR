# Playbook 5 — Phát hiện & ngăn chặn rò rỉ dữ liệu nội bộ

Hệ thống phản ứng sự cố tự động phát hiện hành vi trình duyệt truy cập file
trong thư mục dữ liệu nhạy cảm (nghi ngờ chuẩn bị upload/rò rỉ), cảnh báo qua
Telegram, tạo ticket Jira, chờ quản trị viên phê duyệt, rồi chặn tiến trình
trình duyệt trên endpoint qua Wazuh Active Response.

## Kiến trúc

```
Wazuh (Agent + Manager) → n8n (webhook) → Telegram + Jira
                                          → Form duyệt (admin)
                                          → Active Response (kill browser)
                                          → đóng ticket Jira
```

## Cấu trúc thư mục

```
playbook5/
├── wazuh-manager/
│   ├── local_rules.xml            # Custom rule 100500/100510/100520/100530
│   ├── ossec-conf-snippets.xml    # Block integration + command + active-response
│   ├── custom-n8n                 # Script integration (routing alert -> n8n)
│   └── trigger-ar.sh              # Script test Active Response qua API
├── ubuntu-agent/
│   ├── sensitive_data.rules       # Cấu hình auditd
│   └── kill-browser-linux         # Script AR kill browser (Linux)
└── windows-agent/
    └── kill-browser.py            # Source build kill-browser.exe (Windows)
```

## Triển khai tóm tắt

### 1. Ubuntu Agent
- Cài auditd: `sudo apt install auditd audispd-plugins -y`
- Copy `sensitive_data.rules` → `/etc/audit/rules.d/`, chạy `sudo augenrules --load`
- Đảm bảo Wazuh đọc audit log (ossec.conf có `<location>/var/log/audit/audit.log</location>`, `<log_format>audit</log_format>`)
- Copy `kill-browser-linux` → `/var/ossec/active-response/bin/`
  - `sudo chmod 750` + `sudo chown root:wazuh`

### 2. Windows Agent
- Bật Audit Object Access (auditpol) + đặt SACL Read trên `C:\Sensitive`
- Đảm bảo Wazuh đọc kênh Security (ossec.conf có `<location>Security</location>`),
  query KHÔNG loại Event ID 4663
- Build exe: `pip install pyinstaller` → `pyinstaller --onefile kill-browser.py`
- Copy `dist\kill-browser.exe` → `C:\Program Files (x86)\ossec-agent\active-response\bin\kill-browser-windows.exe`

### 3. Wazuh Manager
- Thêm các rule trong `local_rules.xml`
- Thêm các block trong `ossec-conf-snippets.xml` vào ossec.conf
- Copy `custom-n8n` → `/var/ossec/integrations/`
  - `chmod 750` + `chown root:wazuh`
- Restart manager

### 4. n8n
- Import workflow (file JSON tải riêng từ n8n)
- Cấu hình credential: Telegram, Jira SW Cloud API, Wazuh API (Basic Auth)

## Custom rules

| Rule ID | Level | Mô tả |
|---------|-------|-------|
| 100500  | 10    | Linux: truy cập file nhạy cảm (auditd) |
| 100520  | 12    | Linux: trình duyệt truy cập file nhạy cảm → nghi ngờ upload |
| 100510  | 10    | Windows: truy cập file nhạy cảm (Event 4663) |
| 100530  | 12    | Windows: trình duyệt truy cập file nhạy cảm → nghi ngờ upload |

Rule level 12 (100520, 100530) là trigger gửi alert sang n8n.

## Active Response — lưu ý quan trọng

- Tên file script **phải trùng** tên `<command>` và **bỏ đuôi** `.sh` (Wazuh 4.2+).
- Windows **bắt buộc dùng `.exe`** (build qua PyInstaller); `.cmd`/`.bat` gây lỗi 1317.
- Gọi command qua API phải có tiền tố `!` (vd `!kill-browser-linux`).
- Không khai báo `<rules_id>` trong `<active-response>` → AR không tự chạy,
  chỉ kích hoạt thủ công qua API sau khi admin duyệt (human-in-the-loop).

## MITRE ATT&CK
- T1005 — Data from Local System
- T1567 — Exfiltration Over Web Service
