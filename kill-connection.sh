#!/bin/bash
# Active Response: Kill all established shell connections (sh, bash, csh, ksh, zsh)

# Ghi log
echo "$(date): Killing all established shell connections" >> /var/ossec/logs/active-responses.log

# Lấy danh sách các kết nối shell đang ESTABLISHED
# Định dạng: $5 = địa chỉ local, $6 = địa chỉ remote (có thể chứa cổng và users)
# Ta sẽ lấy cặp địa chỉ:port để kill từng kết nối
ss -nputw | awk '/ESTAB/ && /(sh|bash|csh|ksh|zsh)/ {print $5, $6}' | while read local remote; do
    # Tách IP và port từ địa chỉ (định dạng IP:PORT)
    local_ip=$(echo "$local" | cut -d':' -f1)
    local_port=$(echo "$local" | cut -d':' -f2)
    remote_ip=$(echo "$remote" | cut -d':' -f1)
    remote_port=$(echo "$remote" | cut -d':' -f2)

    # Kill kết nối bằng ss -K (gửi RST)
    # Có thể kill theo cả local và remote để chắc chắn
    echo "$(date): Killing connection $local <-> $remote" >> /var/ossec/logs/active-responses.log
    ss -K src "$local_ip" sport "$local_port" dst "$remote_ip" dport "$remote_port" 2>/dev/null
done

echo "$(date): Finished killing shell connections" >> /var/ossec/logs/active-responses.log
exit 0