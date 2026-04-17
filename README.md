# Network Security Monitoring

## Table of Contents
1. [Network Security Essentials](#network-security-essentials)

## Network Security Essentials
### Network Perimeters: Monitoring and Protecting
1. Examine the firewall logs. Which IP address is performing the port scan?

    We can use this filter to read the .txt file:

    ```bash
    cat firewall_logs.txt | grep BLOCK
    ```
    This will show us all the lines in the firewall logs that contain the word `BLOCK`. From there, we can identify the IP address that is trying to connect to the many ports in the short period of time. The answer is `203.0.113.10`.

2. In the WAF Logs, which single source IP is responsible for all the blocked web attacks?

    We can filter to read only `BLOCK` actions in the WAF logs:

    ```bash
    cat waf_logs.txt | grep BLOCK
    ```
    The answer is `198.51.100.12`.

3. In the VPN logs, how many brute-force attempts failed?

    Based on the VPN logs, we can filter for `FAILED_AUTH` and from ip `45.137.22.13` that performed the brute-force attack:

    ```bash
    grep FAILED_AUTH vpn_logs.txt | grep 45.137.22.13 | wc -l
    ```
    The answer is `90` failed attempts.

4. Which suspicious IP address was found attempting the brute-force attack against the VPN gateway?

    The suspicious IP address is `45.137.22.13`.

### Perimeter Logs: Investigating the Breach
1. Examine the firewall logs. What external IP performed the most reconnaissance?

    We can use this filter in splunk:

    ```txt
    index="network_logs" sourcetype=firewall_logs action=BLOCK
    ```
    Then look in the `src_ip` field to find the IP address that performed the most reconnaissance. The answer is `203.0.113.45`.

2. In the firewall log, Which internal host was targeted by scans?

    We can use this filter in splunk:

    ```txt
    index="network_logs" sourcetype=firewall_logs src_ip="203.0.113.45" action=BLOCK
    ```
    Then look in the `dst_ip` field to find the internal host that was targeted by scans. The answer is `10.0.0.20`.

3. Which username was targeted in VPN logs?

    We can use this filter in splunk since the attacker ip is `203.0.113.45`:

    ```txt
    index="network_logs" sourcetype=vpn_logs src_ip="203.0.113.45"
    ```
    Then look in the `username` field to find the username that was targeted in VPN logs. The answer is `svc_backup`.

4. What internal IP was assigned after successful VPN login?

    The logic to solve this question is to filter for first successful VPN logins from the attacker's IP address `203.0.113.45` with username `svc_backup`:

    ```txt
    index="network_logs" sourcetype=vpn_logs src_ip="203.0.113.45" username=svc_backup  result=SUCCESS | sort + _time
    ```
    The answer is `10.8.0.23`.

5. Which port was used for lateral SMB attempts?

    The logic to solve this question is to filter for SMB attempts from the internal IP address `10.0.0.20`:

    ```txt
    index="network_logs" sourcetype=ids_logs src_ip="10.8.0.23" alert="ET EXPLOIT Possible MS-SMB Lateral Movement" | sort + _time
    ```
    Then look in the `dst_port` field to find the port that was used for lateral SMB attempts. The answer is `445`.

6. In the IDS logs, which host beaconed to the C2?

    The logic to solve this question is to filter for C2 beaconing activity in the IDS logs:

    ```txt
    index="network_logs" sourcetype=ids_logs alert="ET TROJAN Possible C2 Beaconing"
    ```
    Then look in the `src_ip` field to find the host that beaconed to the C2. The answer is `10.0.0.60`.

7. During the investigation, which IP was observed to be associated with C2?

    The logic to solve this question is to filter for C2 beaconing activity in the IDS logs:

    ```txt
    index="network_logs" sourcetype=ids_logs alert="ET TROJAN Possible C2 Beaconing"
    ```
    Then look in the `dst_ip` field to find the IP address that was observed to be associated with C2. The answer is `198.51.100.77`.

8. Which host showed the exfiltration attempts?

    The logic to solve this question is to filter for exfiltration attempts (upload large files) in the IDS logs:

    ```txt
    index="network_logs" sourcetype=ids_logs alert="ET INFO Possible HTTP POST Large Upload"
    ```
    Then look in the `src_ip` field to find the host that showed the exfiltration attempts. The answer is `10.0.0.51`.

