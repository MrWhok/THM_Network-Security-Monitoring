# Network Security Monitoring

## Table of Contents
1. [Network Security Essentials](#network-security-essentials)
2. [Network Discovery Detection](#network-discovery-detection)
3. [Data Exfiltration Detection](#data-exfiltration-detection)
4. [Man-in-the-Middle Detection](#man-in-the-middle-detection)
5. [IDS Fundamentals](#ids-fundamentals)
6. [Snort](#snort)

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


## Data Exfiltration Detection
### Data Exfil: Overview, techniques, and indicators
1. Exfiltrating the data through HTTP comes under which technique?

    The answer is `Network-based`.

### Detection: Data Exfil through DNS Tunneling
1. What is the suspicious domain receiving the DNS traffic?

    To solve this, we can use this filter to find long DNS queries that are indicative of DNS tunneling:

    ```txt
    index="data_exfil" sourcetype="DNS_logs" | where len(query) > 30
    ```
    Then, we can check the `query` field to find the suspicious domain receiving the DNS traffic. The answer is `tunnelcorp.net`.

2. How many suspicious traffic/logs related to dns tunneling were observed?

    We can use this filter to only show `tunnelcorp.net` queries:

    ```txt
    index=data_exfil sourcetype="DNS_logs" | search query="*.tunnelcorp.net" | sort -count
    ```
    The answer is `315`.

3. Which local IP sent the maximum number of suspicious requests?

    We can use previous filter and check the `src_ip` field to find the local IP that sent the maximum number of suspicious requests. The answer is `192.168.1.103`.

### Detection: Data Exfil through FTP
1. How many connections were observed from the guest account?

    We can filter for FTP connections from the guest account:

    ```txt
    (ftp.request.command == "USER" || ftp.request.command == "PASS") and ftp contains "USER root"
    ```
    The answer is `5` connections.

2. Apply the filter; what is the name of the customer-related file exfiltrated from the root account?

    We can filter for FTP connections from the root account:

    ```txt
    (ftp.request.command == "USER" || ftp.request.command == "PASS") and ftp contains "USER root"
    ```
    Then, we can check the each of the result by right click and select `Follow > FTP Stream` to find the name of the customer-related file exfiltrated from the root account. The answer is `customer_data.xlsx`.

3. Which internal IP was found to be sending the largest payload to an external IP?

    We can filter for ftp that have a large payload size:

    ```txt
    ftp && frame.len > 90
    ```
    Then, we can sort based on the length. The answer is `192.168.1.105`.

4. What is the flag hidden inside the ftp stream transferring the CSV file to the suspicious IP?

    We can filter based on the `csv` extension:

    ```txt
    ftp contains "csv"
    ```
    The answer is `THM{ftp_exfil_hidden_flag}`.

### Detection: Data Exfil via HTTP
1. Which internal compromised host was used to exfiltrate this sensitive data?

    We can filter for HTTP POST requests that have a large payload size:

    ```txt
    http.request.method == "POST" and frame.len > 750
    ```
    Then, we can check the `src_ip` field to find the internal compromised host that was used to exfiltrate this sensitive data. The answer is `192.168.1.103`.

2. What's the flag hidden inside the exfiltrated data?

    We can right click on the result of the previous filter and select `Follow > HTTP Stream` to find the flag hidden inside the exfiltrated data. The answer is `THM{http_raw_3xf1ltr4t10n_succ3ss}`.

### Detection: Data Exfil via ICMP
1. What is the flag found in the exfiltrated data through ICMP?

    We can filter for ICMP request packets that have a large payload size:

    ```txt
    icmp.type == 8 and frame.len > 100
    ```
    The answer is `THM{1cmp_3ch0_3xf1ltr4t10n_succ3ss}`.


## Man-in-the-Middle Detection
### Detecting ARP Spoofing
1. How many ARP packets from the gateway MAC Address were observed?

    First we need to filter for ARP response packets:

    ```txt
    arp.opcode == 2
    ```
    The gateway IP, usually end with `.1`, is `192.168.10.1` with mac address `02:aa:bb:cc:00:01`. Then, we can filter for ARP  from the gateway MAC address:

    ```txt
    eth.src == 02:aa:bb:cc:00:01
    ```
    The answer is `10` ARP packets.

2. What MAC address was used by the attacker to impersonate the gateway?

    The attacker will broadcast that the gateway IP address is associated with their own MAC address. So, we need to filter for ARP packets that claim to be from the gateway IP address but have a different MAC address:

    ```txt
    arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1
    ```
    We will find two different MAC addresses claiming to be the gateway. The answer is `02:fe:fe:fe:55:55`.

3. How many Gratuitous ARP replies were observed for 192.168.10.1?

    We can filter for Gratuitous ARP replies that claim to be from the gateway IP address:

    ```txt
    arp.isgratuitous && arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1
    ```
    The answer is `2` Gratuitous ARP replies.

4. How many unique MAC addresses claimed the same IP (192.168.10.1)?

    We can filter for ARP packets that claim to be from the gateway IP address and then count the unique MAC addresses:

    ```txt
    arp.opcode ==2 && _ws.col.info contains "192.168.10.1 is at"
    ```
    The answer is `2` unique MAC addresses.

5. How many ARP spoofing packets were observed in total from the attacker?

    We can filter for ARP packets that claim to be from the gateway IP address but have the attacker's MAC address:

    ```txt
    arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1 && eth.src == 02:fe:fe:fe:55:55
    ```
    The answer is `14` ARP spoofing packets.

### Unmasking DNS Spoofing
1. How many DNS responses were observed for the domain corp-login.acme-corp.local?

    We can filter for DNS response packets that contain the domain `corp-login.acme-corp.local`:

    ```txt
    dns.flags.response == 1 && dns.qry.name == "corp-login.acme-corp.local"
    ```
    The answer is `211` DNS responses.

2. How many DNS requests were observed from the IPs other than 8.8.8.8?

    We can filter DNS response that doesntt come from `8.8.8.8`:
    
    ```txt
    dns.flags.response == 1 && ! (ip.src == 8.8.8.8)
    ```

3. What IP did the attacker’s forged DNS response return for the domain?

    Based on the previous questions the interisting domain is `corp-login.acme-corp.local`. We must make sure that the DNS response is coming from `8.8.8.8`:

    ```txt
    dns.flags.response == 1 && ip.src == 8.8.8.8 && dns.qry.name == "corp-login.acme-corp.local"
    ```
    Oke it valid. Now we need to filter for DNS response that doesntt come from `8.8.8.8` with the same domain:

    ```txt
    dns.flags.response == 1 && ip.src != 8.8.8.8 && dns.qry.name == "corp-login.acme-corp.local"
    ```
    The answer is `192.168.10.55`.

### Spotting SSL Stripping in Action
1. How many POST requests were observed for our domain corp-login.acme-corp.local?

    In the previous, we already know the attacker's IP address is `192.168.10.55`. We can verify tls disappears from victim to the attacker's IP address:

    ```txt
    http && ip.src == 192.168.10.10 && ip.dst == 192.168.10.55
    ```
    The answer is `1`.

2. What's the password of the victim found in the plaintext after successful ssl stripping attack. 

    We can right click on the result of the previous filter and select `Follow > HTTP Stream` to find the password of the victim found in the plaintext after successful ssl stripping attack. The answer is `Secret123!`.


## IDS Fundamentals
### What is an IDS?
1. Can an intrusion detection system (IDS) prevent the threat after it detects it? Yea/Nay

    The answer is `Nay`. An IDS is designed to detect and alert on potential security incidents, but it does not have the capability to prevent or block the threat.

### Types of IDS
1. Which type of IDS is deployed to detect threats throughout the network?

    The answer is `Network Intrusion Detection System`. A Network-based IDS is deployed to monitor and analyze network traffic for signs of malicious activity or policy violations across the entire network.

2. Which IDS leverages both signature-based and anomaly-based detection techniques?

    The answer is `Hybrid IDS`. A Hybrid IDS combines both signature-based and anomaly-based detection techniques to provide a more comprehensive approach to threat detection.

### IDS Example: Snort
1. Which mode of Snort helps us to log the network traffic in a PCAP file?

    The answer is `Packet Logging Mode`. 

2. What is the primary mode of Snort called?

    The answer is `Network Intrusion Detection System Mode`.

### Snort Usage
1. Where is the main directory of Snort that stores its files?

    The main directory of Snort that stores its files is typically located at `/etc/snort`.

2. Which field in the Snort rule indicates the revision number of the rule?

    The field in the Snort rule that indicates the revision number of the rule is `rev`.

3. Which protocol is defined in the sample rule created in the task?

    The protocol defined in the sample rule created in the task is `icmp`.

4. What is the file name that contains custom rules for Snort?

    The file name that contains custom rules for Snort is typically `local.rules`.

### Practice Lab
1. What is the IP address of the machine that tried to connect to the subject machine using SSH?

    We can run snort to analayze pcap file by using this command:
    
    ```bash
    sudo snort -q -l /var/log/snort -r Intro_to_IDS.pcap -A console -c /etc/snort/snort.conf
    ```
    Then, we can check the output for any SSH connection attempts. The answer is `10.11.90.211`.

2. What other rule message besides the SSH message is detected in the PCAP file? 

    The answer is `Ping Detected`.

3. What is the sid of the rule that detects SSH?

    The answer is `1000002`.

## Snort
### Interactive Material and VM
1. Navigate to the Task-Exercises folder and run the command "./.easy.sh" and write the output

    The answer is `Too Easy!`.

### Introduction to IDS/IPS
1. Which IDS or IPS type can help you stop the threats on a local machine?

    The answer is `HIPS`.

2. Which IDS or IPS type can help you detect threats on a local network?

    The answer is `NIDS`.

3. Which IDS or IPS type can help you detect the threats on a local machine?

    The answer is `HIDS`.

4. Which IDS or IPS type can help you stop the threats on a local network?

    The answer is `NIPS`.

5. Which described solution works by detecting anomalies in the network?

    The answer is `NBA`. NBA stands for Network Behavior Analysis, which is a technique used in intrusion detection systems to identify unusual patterns of network traffic that may indicate a security threat.

6. According to the official description of the snort, what kind of NIPS is it?

    The answer is `full-blown`.

7. NBA training period is also known as ...

    The answer is `baselining`.

### First Interaction with Snort
1. Run the Snort instance and check the build number.

    We can use this command to check the build number of Snort:

    ```bash
    snort -V
    ```
    The answer is `149`.

2. Test the current instance with "/etc/snort/snort.conf" file and check how many rules are loaded with the current build.

    We can use this command to test the current instance of Snort with the configuration file and check how many rules are loaded:

    ```bash
    sudo snort -c /etc/snort/snort.conf -T
    ```
    The answer is `4151`.

3. Test the current instance with "/etc/snort/snortv2.conf" file and check how many rules are loaded with the current build.

    We can use this command to test the current instance of Snort with the new configuration file and check how many rules are loaded:

    ```bash
    sudo snort -c /etc/snort/snortv2.conf -T
    ```
    The answer is `1`.

### Operation Mode 2: Packet Logger Mode
1. Investigate the traffic with the default configuration file with ASCII mode. sudo snort -dev -K ASCII -l .. Execute the traffic generator script and choose "TASK-6 Exercise". Wait until the traffic ends, then stop the Snort instance. Now analyse the output summary and answer the question. sudo ./traffic-generator.sh. Now, you should have the logs in the current directory. Navigate to folder "145.254.160.237". What is the source port used to connect port 53?

    To solve this challenge, we can run snort in packet logger mode with ASCII output:

    ```bash
    sudo snort -dev -K ASCII -l .
    ```
    Then, we can execute the traffic generator script and choose "TASK-6 Exercise":

    ```bash
    sudo ./traffic-generator.sh
    ```
    After the traffic ends, we can modify the permissions of the output directory to allow us to read the logs:

    ```bash
    sudo chown ubuntu -R 145.254.160.237
    ```
    Then, we can navigate to the folder `145.254.160.237` and read `UDP:3009-53`. The source port used to connect to port 53 is `3009`.

2. Use snort.log.1640048004. Read the snort.log file with Snort; what is the IP ID of the 10th packet? snort -r snort.log.1640048004 -n 10

    To solve this challenge, we can read the snort.log file with Snort and specify to read only the first 10 packets:

    ```bash
    snort -r snort.log.1640048004 -n 10
    ```
    Then, we can check the output for the IP ID of the 10th packet. The answer is `49313`.

3. Read the "snort.log.1640048004" file with Snort; what is the referer of the 4th packet?

    We can read the snort.log file with Snort and specify to read only the first 4 packets:

    ```bash
    snort -dvr snort.log.1640048004 -n 4
    ```
    Then, we can check the output for the referer of the 4th packet. The answer is `http://www.ethereal.com/development.html`.

4. Read the "snort.log.1640048004" file with Snort; what is the Ack number of the 8th packet?

    We can read the snort.log file with Snort and specify to read only the first 8 packets:

    ```bash
    snort -r snort.log.1640048004 -n 8
    ```
    Then, we can check the output for the Ack number of the 8th packet. The answer is `0x38AFFFF3`.

5. Read the "snort.log.1640048004" file with Snort; what is the number of the "TCP port 80" packets?

    We can read the snort.log file with Snort and filter for packets that contain "TCP port 80":

    ```bash
    snort -r snort.log.1640048004 'tcp and port 80' 
    ```
    Then we can check the total output, in the end of the output. The answer is `41`.

### Operation Mode 3: IDS/IPS
1. Investigate the traffic with the default configuration file. `sudo snort -c /etc/snort/snort.conf -A full -l .`. Execute the traffic generator script and choose "TASK-7 Exercise". Wait until the traffic stops, then stop the Snort instance. Now analyse the output summary and answer the question. `sudo ./traffic-generator.sh`. What is the number of the detected HTTP GET methods?

    To solve this challenge, we can run snort in IDS mode with full alert output:

    ```bash
    sudo snort -c /etc/snort/snort.conf -A full -l .
    ```
    Then, we can execute the traffic generator script and choose "TASK-7 Exercise":

    ```bash
    sudo ./traffic-generator.sh
    ```
    After the traffic stops, we can check the output summary for the number of detected HTTP GET methods. The answer is `2`.

### Operation Mode 4: PCAP Investigation
1. Investigate the mx-1.pcap file with the default configuration file. `sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap`. What is the number of the generated alerts?

    To solve this challenge, we can investigate the `mx-1.pcap` file with Snort using the default configuration file:

    ```bash
    sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap
    ```
    Then, we can check the output summary for the number of generated alerts. The answer is `170`.

2. Keep reading the output. How many TCP Segments are Queued?

    We can check the output for the number of TCP Segments that are Queued. The answer is `18`.

3. Keep reading the output. How many "HTTP response headers" were extracted?

    We can check the output for the number of "HTTP response headers" that were extracted. The answer is `3`.

4. Investigate the mx-1.pcap file with the second configuration file. `sudo snort -c /etc/snort/snortv2.conf -A full -l . -r mx-1.pcap`. What is the number of the generated alerts?

    To solve this challenge, we can investigate the `mx-1.pcap` file with Snort using the second configuration file:

    ```bash
    sudo snort -c /etc/snort/snortv2.conf -A full -l . -r mx-1.pcap
    ```
    Then, we can check the output summary for the number of generated alerts. The answer is `68`.

5. Investigate the mx-2.pcap file with the default configuration file. `sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-2.pcap`. What is the number of the generated alerts?

    To solve this challenge, we can investigate the `mx-2.pcap` file with Snort using the default configuration file:

    ```bash
    sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-2.pcap
    ```
    Then, we can check the output summary for the number of generated alerts. The answer is `340`.

6. Keep reading the output. What is the number of the detected TCP packets?

    We can check the output for the number of detected TCP packets. The answer is `82`.

7. Investigate the mx-2.pcap and mx-3.pcap files with the default configuration file. `sudo snort -c /etc/snort/snort.conf -A full -l . --pcap-list="mx-2.pcap mx-3.pcap"`. What is the number of the generated alerts?

    To solve this challenge, we can investigate the `mx-2.pcap` and `mx-3.pcap` files with Snort using the default configuration file:

    ```bash
    sudo snort -c /etc/snort/snort.conf -A full -l . --pcap-list="mx-2.pcap mx-3.pcap"
    ```
    Then, we can check the output summary for the number of generated alerts. The answer is `1020`.

### Snort Rule Structure
1. Use "task9.pcap". Write a rule to filter IP ID "35369" and run it against the given pcap file. What is the request name of the detected packet? You may use this command: "snort -c local.rules -A full -l . -r task9.pcap"

    To solve this challenge, we can create a Snort rule in the `local.rules` file to filter for packets with IP ID "35369". The rule would look like this:

    ```txt
    alert icmp any any <> any any (msg: "1 question"; id:35369; sid: 1000002; rev:1;)
    ```
    Then, we can run Snort against the `task9.pcap` file using the command:

    ```bash
    snort -c local.rules -A full -l . -r task9.pcap
    ```
    After running the command, we can check the output for the request name of the detected packet (in the alert file). The answer is `TIMESTAMP REQUEST`.

2. Clear the previous alert file and comment out the old rules. Create a rule to filter packets with Syn flag and run it against the given pcap file. What is the number of detected packets?

    To solve this challenge, we can first clear the previous alert file and comment out the old rules in the `local.rules` file. Then, we can create a new rule to filter for packets with the SYN flag set. The rule would look like this:

    ```txt
    alert tcp any any <> any any (msg: "SYN TEST"; flags:S;  sid: 1000003; rev:1;)
    ```
    After adding the new rule, we can run Snort against the `task9.pcap` file using the command:

    ```bash
    snort -c local.rules -A full -l . -r task9.pcap
    ```
    After running the command, we can check the output for the number of detected packets with the SYN flag. The answer is `1`.

3. Clear the previous alert file and comment out the old rules. Write a rule to filter packets with Push-Ack flags and run it against the given pcap file. What is the number of detected packets?

    To solve this challenge, we can first clear the previous alert file and comment out the old rules in the `local.rules` file. Then, we can create a new rule to filter for packets with the Push and Ack flags set. The rule would look like this:

    ```txt
    alert tcp any any <> any any (msg: "PUSH-ACK TEST"; flags:PA; sid: 1000004; rev:1;)
    ```
    After adding the new rule, we can run Snort against the `task9.pcap` file using the command:

    ```bash
    snort -c local.rules -A full -l . -r task9.pcap
    ```
    After running the command, we can check the output for the number of detected packets with the Push and Ack flags. The answer is `216`.

4. Clear the previous alert file and comment out the old rules. Create a rule to filter UDP packets with the same source and destination IP and run it against the given pcap file. What is the number of packets that show the same source and destination address?

    To solve this challenge, we can first clear the previous alert file and comment out the old rules in the `local.rules` file. Then, we can create a new rule to filter for UDP packets where the source and destination IP addresses are the same. The rule would look like this:

    ```txt
    alert udp any any <> any any (msg: "SAME-IP TEST";  sameip; sid: 1000005; rev:1;)
    ```
    After adding the new rule, we can run Snort against the `task9.pcap` file using the command:

    ```bash
    snort -c local.rules -A full -l . -r task9.pcap
    ```
    After running the command, we can check the output for the number of packets that show the same source and destination address. The answer is `7`.

5. Case Example - An analyst modified an existing rule successfully. Which rule option must the analyst change after the implementation?

    The answer is `rev`. The `rev` (revision) option in a Snort rule indicates the version of the rule. When an analyst modifies an existing rule, they should increment the revision number to indicate that the rule has been updated. This helps in tracking changes and ensuring that the latest version of the rule is being used.
