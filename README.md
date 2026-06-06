# Deploy Wazuh Docker in single node configuration

This deployment is defined in the `docker-compose.yml` file with one Wazuh manager containers, one Wazuh indexer containers, and one Wazuh dashboard container. It can be deployed by following these steps: 

1) Increase max_map_count on your host (Linux). This command must be run with root permissions:
```
$ sysctl -w vm.max_map_count=262144
```
2) Run the certificate creation script:
```
$ docker compose -f generate-indexer-certs.yml run --rm generator
```
3) Start the environment with docker-compose:

- In the foregroud:
```
$ docker compose up
```
- In the background:
```
$ docker compose up -d
```

The environment takes about 1 minute to get up (depending on your Docker host) for the first time since Wazuh Indexer must be started for the first time and the indexes and index patterns must be generated.

## 3.1. Permission Principles (Nguyên tắc quyền hạn)

**Vietnamese:**
Wazuh Integrator chạy với user wazuh (hoặc ossec tùy phiên bản).
File script phải thuộc sở hữu root:root và có permission 755 (tương đương rwxr-xr-x).
User wazuh chỉ được phép đọc và thực thi script, không được ghi lên file script. Nếu script có quyền ghi cho user wazuh (ví dụ 775 với owner là wazuh, hoặc 777), Integrator sẽ từ chối thực thi vì lý do bảo mật (ngăn chặn leo thang đặc quyền).

**English Summary:**
Wazuh Integrator runs under the wazuh user (or ossec depending on version). Custom integration scripts must be owned by root:root with 755 permissions (rwxr-xr-x), allowing the wazuh user only read and execute access. Write permissions for the wazuh user (such as 775 or 777) will cause the Integrator to refuse execution as a security measure to prevent privilege escalation attacks.

**Setup bash commands:**
```bash
docker exec -it <wazuh-manager> bash
chmod 755 /var/ossec/integrations/custom-n8n.py
exit
docker exec -it <wazuh-manager> /var/ossec/bin/wazuh-control restart integrator
```
