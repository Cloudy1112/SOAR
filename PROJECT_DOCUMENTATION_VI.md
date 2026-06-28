# Tài Liệu Dự Án Wazuh Single Node

## Tổng Quan Dự Án

Đây là một dự án triển khai **Wazuh SIEM** (Security Information and Event Management) trong cấu hình **Single Node** sử dụng **Docker Compose**. Dự án tích hợp với **n8n** (nền tảng tự động hóa workflow) để xử lý các cảnh báo bảo mật từ Wazuh.

---

## 📁 Cấu Trúc Thư Mục và Chức Năng File

### 📦 Thư Mục Gốc `/home/van/Singlenode/`

```
Singlenode/
├── Brute Force.json          # Workflow n8n cho phát hiện brute force
├── README.md                 # Hướng dẫn triển khai
├── docker-compose.yml        # Cấu hình Docker cho toàn bộ stack
├── generate-indexer-certs.yml # Script tạo SSL certificates cho Indexer
├── config/                   # Thư mục cấu hình chính
├── n8n_data/                 # Dữ liệu n8n (workflows, executions)
├── shared_logs/              # Logs được chia sẻ giữa các container
└── .git/                     # Git repository
```

---

## 📄 File Tại Thư Mục Gốc

### 1. **README.md**
- **Chức năng**: Hướng dẫn triển khai toàn bộ hệ thống
- **Nội dung chính**:
  - Các bước cài đặt (tăng `max_map_count`, tạo certs, chạy docker-compose)
  - Thông tin về Docker containers (Wazuh Manager, Indexer, Dashboard)
  - Hướng dẫn cấu hình quyền hạn (Permission Principles) cho script tích hợp
  - Lệnh bash để khắc phục quyền truy cập script

### 2. **docker-compose.yml**
- **Chức năng**: Định nghĩa toàn bộ stack Docker cho hệ thống
- **Chứa cấu hình cho**:
  - **wazuh.manager** (Phần mềm quản lý bảo mật chính)
  - **wazuh.indexer** (Cơ sở dữ liệu lưu trữ các sự kiện)
  - **wazuh.dashboard** (Dashboard hiển thị thị)
  - **n8n** (Nền tảng tự động hóa)
- **Biến môi trường**: Cấu hình xác thực, SSL certificates, cổng mạng

### 3. **generate-indexer-certs.yml**
- **Chức năng**: Tạo SSL/TLS certificates cho Wazuh Indexer
- **Sử dụng**: Chạy trước khi khởi động Docker Compose
- **Lệnh**: `docker compose -f generate-indexer-certs.yml run --rm generator`

### 4. **Brute Force.json**
- **Chức năng**: Workflow n8n để xử lý cảnh báo brute force attacks
- **Nội dung**:
  - Webhook nhận dữ liệu từ Wazuh (`wazuh-alert/brute-force`)
  - Cấu hình xử lý các thông báo tấn công brute force
  - Định nghĩa các node trong n8n workflow

---

## 🔧 Thư Mục `config/`

### Cấu Trúc
```
config/
├── certs.yml                 # Cấu hình node cho SSL certificates
├── wazuh_cluster/            # Cấu hình Wazuh Manager
│   └── wazuh_manager.conf    # File cấu hình chính của Wazuh
├── wazuh_dashboard/          # Cấu hình Dashboard
│   ├── opensearch_dashboards.yml
│   └── wazuh.yml
├── wazuh_etc/                # File cấu hình hệ thống Wazuh
│   ├── agent.conf            # Cấu hình Wazuh Agents
│   ├── local_rules.xml       # Các quy tắc bảo mật tùy chỉnh
│   └── sensitive-username.txt# Danh sách username nhạy cảm
├── wazuh_indexer/            # Cấu hình Elasticsearch/OpenSearch
│   ├── internal_users.yml    # Người dùng nội bộ
│   └── wazuh.indexer.yml     # Cấu hình Indexer
├── wazuh_indexer_ssl_certs/  # Thư mục SSL certificates (được tạo)
└── wazuh_integrations/       # Script tích hợp tùy chỉnh
    ├── custom-n8n.py         # Script tích hợp n8n chung
    ├── custom-n8n-brute-force.py  # Script xử lý brute force
    ├── custom-n8n-ransomware.py   # Script xử lý ransomware
    
```

---

## 🔑 Chi Tiết Các File Cấu Hình

### **certs.yml**
- **Chức năng**: Định nghĩa các node trong hệ thống để tạo SSL certificates
- **Chứa**: Cấu hình cho Indexer, Server (Manager), và Dashboard

### **wazuh_cluster/wazuh_manager.conf**
- **Chức năng**: File cấu hình chính của Wazuh Manager
- **Nội dung**:
  - Cấu hình toàn cục (global settings)
  - Bật JSON output và logging
  - Cấu hình email notifications
  - Ngưỡng cảnh báo (`log_alert_level`, `email_alert_level`)
  - Tích hợp với n8n thông qua webhook
  - Định nghĩa rule IDs cho phát hiện brute force (Windows: 2502, 5758, 5551, 5712; SSH: 5710, 5503)

### **wazuh_dashboard/opensearch_dashboards.yml**
- **Chức năng**: Cấu hình OpenSearch Dashboard (giao diện hiển thị)
- **Nội dung**: Port, hostname, URL kết nối đến Indexer

### **wazuh_dashboard/wazuh.yml**
- **Chức năng**: Cấu hình plugin Wazuh cho Dashboard
- **Nội dung**: Cài đặt xác thực, backend URL

### **wazuh_etc/agent.conf**
- **Chức năng**: Cấu hình chung cho các Wazuh Agents
- **Nội dung**: Những file/log nào cần theo dõi, độ tần suất scan

### **wazuh_etc/local_rules.xml**
- **Chức năng**: Quy tắc bảo mật tùy chỉnh của người dùng
- **Nội dung**: Định nghĩa các rules phát hiện các loại tấn công cụ thể

### **wazuh_etc/sensitive-username.txt**
- **Chức năng**: Danh sách username nhạy cảm (admin, root, etc.)
- **Sử dụng**: Để phát hiện các nỗ lực truy cập không hợp pháp

### **wazuh_indexer/internal_users.yml**
- **Chức năng**: Cấu hình người dùng nội bộ cho Indexer
- **Nội dung**: Tên người dùng, mật khẩu (hash), vai trò

### **wazuh_indexer/wazuh.indexer.yml**
- **Chức năng**: Cấu hình chính của Wazuh Indexer
- **Nội dung**: Port (9200), hostname, SSL/TLS settings, cluster settings

---

## 🚀 Script Tích Hợp (wazuh_integrations/)

### **custom-n8n.py** (Script Chính)
- **Chức năng**: Gửi cảnh báo từ Wazuh đến n8n qua webhook
- **Cách hoạt động**:
  1. Nhận dữ liệu cảnh báo từ Wazuh
  2. Gửi POST request đến webhook URL của n8n
  3. n8n xử lý cảnh báo (gửi notification, tạo ticket, etc.)

### **custom-n8n-brute-force.py**
- **Chức năng**: Xử lý riêng cho cảnh báo brute force attacks
- **Đặc điểm**: Lọc và xử lý các cảnh báo thất bại trong việc đăng nhập

### **custom-n8n-ransomware.py**
- **Chức năng**: Xử lý riêng cho cảnh báo ransomware detection
- **Đặc điểm**: Phát hiện các hoạt động tạo file đáng ngờ

### **slack.py** & **pagerduty/** & **virustotal.py**
- **Chức năng**: Các script tích hợp với nền tảng bên ngoài
- **slack.py**: Gửi thông báo đến Slack channel
- **pagerduty**: Tạo incident trong PagerDuty
- **virustotal.py**: Kiểm tra hash file/URL với VirusTotal

---

## 📊 Thư Mục `n8n_data/`

### Cấu Trúc
```
n8n_data/
├── config          # Cấu hình n8n
├── nodes/          # Các node workflow tùy chỉnh
│   └── package.json
└── storage/        # Lưu trữ workflow và executions
    └── workflows/
        └── srtqNmIX3TTwAyb8/     # ID workflow
            └── executions/        # Các lần chạy workflow
                ├── 29/
                ├── 3615/
                ├── 3616/
                ├── 3617/
                ├── 3618/
                ├── 3619/
                └── 3620/
                    └── binary_data/  # Dữ liệu nhị phân từ execution
```

### **Chức năng**
- Lưu trữ tất cả workflow n8n đã tạo
- Lưu trữ log executions (những lần workflow chạy)
- Lưu trữ dữ liệu nhị phân từ các execution (webhook data, etc.)

---

## 📝 Thư Mục `shared_logs/`

- **Chức năng**: Thư mục chia sẻ logs giữa các Docker container
- **Nội dung**: Logs từ Wazuh Manager, Indexer, Dashboard, và các service khác
- **Sử dụng**: Debug, monitoring, audit trail

---

## 🔐 Nguyên Tắc Quyền Hạn (Permission Principles)

### ⚠️ Quan Trọng
- Wazuh Integrator chạy với user `wazuh` (hoặc `ossec`)
- Script tích hợp phải:
  - **Chủ sở hữu**: `root:root`
  - **Quyền truy cập**: `755` (rwxr-xr-x)
  - **Lý do**: Ngăn chặn leo thang đặc quyền (privilege escalation)

### ✅ Cấu hình Đúng
```bash
# Truy cập vào Wazuh Manager container
docker exec -it wazuh.manager bash

# Thiết lập quyền cho script
chmod 755 /var/ossec/integrations/custom-n8n.py
chown root:root /var/ossec/integrations/custom-n8n.py

# Khởi động lại Integrator
/var/ossec/bin/wazuh-control restart integrator
exit
```

---

## 🏗️ Kiến Trúc Toàn Bộ Hệ Thống

```
┌─────────────────────────────────────────────────────────────────┐
│                       DOCKER COMPOSE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐   │
│  │  Wazuh Manager   │  │  Wazuh Indexer   │  │   Dashboard  │   │
│  │  (Port 55000)    │  │  (Port 9200)     │  │  (Port 443)  │   │
│  │                  │  │                  │  │              │   │
│  │  - Monitors      │  │  - Stores        │  │  - Shows     │   │
│  │  - Detects       │  │  - Indexes       │  │  - Visualizes│   │
│  │  - Integrates    │  │  - Searches      │  │  - Reports   │   │
│  └────────┬─────────┘  └────────┬─────────┘  └──────┬───────┘   │
│           │                     │                    │            │
│           └─────────────────────┴────────────────────┘            │
│                          │                                         │
│  ┌────────────────────────▼────────────────────────┐              │
│  │         n8n (Automation Platform)              │              │
│  │  - Webhook receiver                            │              │
│  │  - Alert processing                            │              │
│  │  - Integration with external services:         │              │
│  │    • Slack, PagerDuty, VirusTotal             │              │
│  └─────────────────────────────────────────────────┘              │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Quy Trình Phát Hiện Cảnh Báo

```
1. Wazuh Agent → Wazuh Manager
   (Thu thập logs từ endpoints)

2. Wazuh Manager → Phân tích
   (Áp dụng rules và phát hiện)

3. Phát hiện cảnh báo → Webhook n8n
   (custom-n8n.py script được kích hoạt)

4. n8n xử lý cảnh báo
   (Phân loại, gửi notification)

5. Gửi đến các hệ thống bên ngoài
   (Slack, PagerDuty, VirusTotal, etc.)

6. Lưu trữ → Wazuh Indexer → Dashboard
   (Hiển thị cho người dùng)
```

---

## 📌 Các Rule ID Quan Trọng (từ wazuh_manager.conf)

| OS | Loại Tấn Công | Rule IDs |
|----|--------------|----------|
| Windows | Brute Force | 2502, 5758, 5551, 5712 |
| Linux/SSH | Brute Force | 5710, 5503 |

---

## ✨ Tóm Tắt

Dự án này là một **hệ thống giám sát bảo mật toàn diện (SIEM)** gồm:
- ✅ **Wazuh** - Thu thập và phân tích logs bảo mật
- ✅ **OpenSearch** - Lưu trữ và tìm kiếm dữ liệu
- ✅ **n8n** - Tự động hóa xử lý cảnh báo
- ✅ **Integrações** - Kết nối với Slack, PagerDuty, VirusTotal, etc.

Mục đích chính: **Phát hiện và phản ứng nhanh chóng với các sự cố bảo mật**
