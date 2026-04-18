# Network Security Monitoring

## Table of Contents
1. [Network Security Essentials](#network-security-essentials)
2. [Network Discovery Detection](#network-discovery-detection)

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


## Network Discovery Detection
### Network Discovery
1. What do attackers scan, other than, IP addresses, ports, and OS version, in order to identify vulnerabilities in a network?

    The answer is `Services`.

### External vs Internal Scanning
1. Which file contains logs that showcase internal scanning activity?

    We can identify internal scanning activity by looking for logs that show connections from internal IP addresses to other internal IP addresses. The file that contains logs showcasing internal scanning activity is `log-session-2.csv`.

2. How many log entries are present for the internal IP performing internal scanning activity?

    The answer is `2276`.

3. What is the external IP address that is performing external scanning activity?

    We can check `log-session-0.csv` or `log-session-1.csv` for connections from external IP addresses to internal IP addresses. The external IP address that is performing external scanning activity is `203.0.113.25`.

### Horizontal vs Vertical Scanning
1. One of the log files contains evidence of a horizontal scan. Which IP range was scanned? Format X.X.X.X/X

    We can find horizontal scanning in the `log-session-2.csv` file by looking for connections from one internal IP address to multiple other internal IP addresses. The IP range is `203.0.113.2 - 203.0.113.254`. The answer is `203.0.113.0/24`.

2. In the same log file, there is one IP address on which a vertical scan is performed. Which IP address is this?

    The answer is `192.168.230.145`.

3. On one of the IP addresses, only a few ports are scanned which host common services. Which are the ports that are scanned on this IP address?Format: port1, port2, port3 in ascending order.

    We can use this filter to reduce the IP address based on the hint:

    ```bash
    cat log-session-2.csv |cut -d "," -f5|grep -v "203.0"|grep -v "230.145"|sort|uniq -c
    ```
    Then, we can check specifically for the IP address `192.168.230.1`. The answer is `80, 445, 3389`.


### The Mechanics of Scanning
1. Which source IP performs a ping sweep attack across a whole subnet?

    We can identify a ping sweep attack by looking for connections from one source IP address to multiple destination IP addresses within the same subnet. The source IP that performs a ping sweep attack across a whole subnet is `192.168.230.127`.

2. The zeek.conn.conn_state value shows the connection state. Using the information provided by this value, identify the type of scan being performed by 203.0.113.25 against 192.168.230.145

    We can identify the type of scan being performed by looking at the `zeek.conn.conn_state` value and add filter for the source and destination IP addresses. The value of `zeek.conn.conn_state` is `s0`. It means that the connection was attempted but no response was received, which is indicative of a `TCP SYN Scan`.

3. Is there any UDP scanning attempt in the logs? Y/N

    We can filter:

    ```txt
    network.protocol: "UDP"
    ```
    We will find `UDP` result but the destination ip is `239.255.255.250` which is a multicast address used for service discovery and not indicative of a scanning attempt. Therefore, the answer is `N`.
