# Playbook 6 — Phát hiện đánh cắp thông tin xác thực & xóa dấu vết

Phát hiện hành vi Credential Dumping (đọc file mật khẩu hệ thống `/etc/shadow`)
và Anti-forensics (xóa/làm rỗng log để che dấu vết), cảnh báo qua Telegram,
tạo ticket Jira, và tự động khóa tài khoản người dùng thực hiện hành vi.

> Triển khai trên Linux (Ubuntu). Windows (LSASS/SAM, xóa Event Log) là hướng mở rộng.

## Kiến trúc

```
auditd (Ubuntu) → Wazuh rule 100600/100610 → custom-n8n → webhook /credential-theft
   → n8n: Switch (phân loại) → Extract Data
   → Telegram + Jira
   → Active Response: disable-user (khóa tài khoản tự động)
   → đóng ticket Jira
```

## Cấu trúc thư mục

```
playbook6/
├── wazuh-manager/
│   ├── local_rules.xml              # Rule 100600/100601/100610
│   ├── ossec-conf-snippets.xml      # Block command + active-response
│   ├── custom-n8n-routing.py        # Trích đoạn routing thêm vào custom-n8n
│   └── trigger-disable-user.sh      # Script test AR qua API
└── ubuntu-agent/
    ├── credential-theft.rules       # Cấu hình auditd
    └── disable-user                 # Script AR khóa tài khoản (động)
```

## Custom rules

| Rule ID | Level | Mô tả |
|---------|-------|-------|
| 100600  | 12    | Credential Dumping: đọc file mật khẩu hệ thống (T1003) |
| 100601  | 3     | Loại trừ tiến trình hệ thống/sudo đọc shadow hợp lệ (giảm false positive) |
| 100610  | 13    | Anti-forensics: xóa/sửa file log (T1070) — mức nghiêm trọng nhất |

## Triển khai tóm tắt

### Ubuntu Agent
1. Copy `credential-theft.rules` → `/etc/audit/rules.d/`, chạy `sudo augenrules --load`
2. Copy `disable-user` → `/var/ossec/active-response/bin/`
   - `sudo chmod 750` + `sudo chown root:wazuh`
3. Đảm bảo Wazuh đọc audit log (ossec.conf có `<location>/var/log/audit/audit.log</location>`)

### Wazuh Manager
1. Thêm rule trong `local_rules.xml`
2. Thêm block trong `ossec-conf-snippets.xml` vào ossec.conf
3. Thêm routing rule 100600/100610 vào script `custom-n8n` (xem custom-n8n-routing.py)
4. Restart manager

### n8n
- Import workflow (file JSON tải riêng)
- Node Disable User truyền username động qua arguments:
  ```json
  {"command": "!disable-user", "arguments": ["{{ $('Extract Data').item.json.user }}"]}
  ```

## Active Response — lưu ý

- Script `disable-user` lấy username **động** từ `extra_args` (do n8n truyền), khóa đúng kẻ tấn công.
- Có **whitelist** bảo vệ tài khoản quản trị (root, quien) — không bao giờ tự khóa người vận hành.
- Gọi command qua API phải có tiền tố `!` (`!disable-user`).
- Mở lại user: `sudo usermod -U <username>` | Kiểm tra: `sudo passwd -S <username>` (L=locked).

## Kịch bản demo

```bash
# 1. Cho thấy log đang có nội dung
sudo tail -20 /var/log/auth.log
ls -lh /var/log/auth.log          # vd 45K

# 2. Attacker (đăng nhập bằng testuser1 qua SSH để AUID đúng)
ssh testuser1@localhost
sudo cat /etc/shadow              # → alert Credential Dumping (100600)
sudo truncate -s 0 /var/log/auth.log   # → alert Anti-forensics (100610)
exit

# 3. Chứng minh log bị xóa sạch
ls -lh /var/log/auth.log          # → 0 bytes

# 4. Nhưng Wazuh đã bắt được (Dashboard/Telegram/Jira) + testuser1 bị khóa
sudo passwd -S testuser1          # → L (locked)
```

**Điểm nhấn:** dù attacker xóa log local, Wazuh Manager đã lưu sự kiện realtime
trước đó → vô hiệu hóa nỗ lực che giấu (giá trị của SIEM tập trung).

## MITRE ATT&CK
- T1003 — OS Credential Dumping (Credential Access)
- T1070 — Indicator Removal (Defense Evasion)
