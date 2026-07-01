# Deploy Wazuh Docker in a Single-Node Configuration

This deployment provides a SOAR-integrated environment that combines n8n and Wazuh, and it is deployed using Docker. The stack includes one Wazuh manager container, one Wazuh indexer container, and one Wazuh dashboard container.

## Project Structure

The repository is organized as follows:

- docker-compose.yml: the main Docker Compose configuration for the Wazuh stack
- generate-indexer-certs.yml: helper file used to generate certificates for the indexer
- config/: contains Wazuh configuration files such as manager settings, dashboard settings, indexer settings, and custom integrations
- config on Agent/: contains agent-side configuration files for:
  - Active response scripts
  - Auditd rules for Linux systems
  - Sysmon configuration for Windows systems
- workflow-n8n/: contains n8n workflow definitions
- n8n_data/: stores n8n runtime data and workflow execution information

> Note: The config on Agent folder is used to install and configure agent-side components such as active response scripts, Linux Auditd rules, and Windows Sysmon rules.

## Deploy Docker in Single-Node Mode

1. Increase the max_map_count value on your host (Linux). This command must be run with root permissions:

```bash
sudo sysctl -w vm.max_map_count=262144
```

2. Run the certificate generation script:

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

3. Start the environment with Docker Compose:

- In the foreground:

```bash
docker compose up
```

- In the background:

```bash
docker compose up -d
```

The environment usually takes about 1 minute to become fully ready the first time, because the Wazuh indexer must initialize and generate the required indexes and index patterns.

## Permission Principles

Wazuh Integrator runs under the wazuh user (or ossec depending on the version). Custom integration scripts must be owned by root:root and have 755 permissions (rwxr-xr-x), allowing the wazuh user to read and execute them, but not modify them. If the wazuh user is granted write access (for example, through 775 or 777 permissions), the Integrator will refuse to execute the script as a security measure to prevent privilege escalation.

### Example Commands

After entering the Wazuh manager container, set the correct permissions for the integration files:

```bash
docker exec -it <wazuh-manager> bash
chmod 755 /var/ossec/integrations/custom-n8n.py
chmod 755 /var/ossec/integrations/custom-n8n-brute-force.py
chmod 755 /var/ossec/integrations/custom-n8n-routing.py
chmod 755 /var/ossec/integrations/custom-n8n-webshell.py
exit
docker exec -it <wazuh-manager> /var/ossec/bin/wazuh-control restart integrator
```

