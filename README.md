# HTB-CDSA---ALL-THE-ANSWERS

**Incident Handling Process**  
Cyber Kill Chain   
Task 1 - weaponize  
Incident Handling Process Overview   
Task 1 - False  
Preparation Stage (Part 1)   
Task 1 - jump bag  
Task 2 - true  
Preparation Stage (Part 2)  
Task 1 - DMARC  
Task 2 - true  
Detection & Analysis Stage (Part 1)  
Task 1 - true  
Detection & Analysis Stage (Part 2)  
Task 1 - ioc  
Containment, Eradication, & Recovery Stage  
Task 1 - false  
Post-Incident Activity Stage  
Task 1 - true  


##Security Monitoring & SIEM Fundamentals  
Introduction To The Elastic Stack  
Task 1 - anni  
Task 2 - 8  
SOC Definition & Fundamentals  
Task 1 - true  
SIEM Visualization Example 1: Failed Logon Attempts (All Users)  
Task 1 - 2  
SIEM Visualization Example 2: Failed Logon Attempts (Disabled Users)  
Task 1 - interactive  
Task 2 - *admin*  
SIEM Visualization Example 3: Successful RDP Logon Related To Service Accounts  
Task 1 - 192.168.28.130  
SIEM Visualization Example 4: Users Added Or Removed From A Local Group (Within A Specific Timeframe)  
Task 1 - 2023-03-05  
Skills Assessment  
Task 1 - Consult with IT Operations  
Task 2 - Escalate to a Tier 2/3 analyst  
Task 3 - Nothing suspicious  
Task 4 - Escalate to a Tier 2/3 analyst  
Task 5 - Consult with IT Operations  
Task 6 - Consult with IT Operations  
Task 7 - Escalate to a Tier 2/3 analyst  


##Windows Event Logs & Finding Evil  
Windows Event Logging Basics  
Task 1 - TiWorker.exe  
Task 2 - 10:23:50  
Analyzing Evil With Sysmon & Event Logs  
Task 1 - 51F2305DCF385056C68F7CCF5B1B3B9304865CEF1257947D4AD6EF5FAD2E3B13  
Task 2 - 8A3CD3CF2249E9971806B15C75A892E6A44CCA5FF5EA5CA89FDA951CD2C09AA9  
Task 3 - 5e4ffd54b3849aa720ed39f50185e533  
Tapping Into ETW  
Task 1 - GetTokenInformation  
Get-WinEvent  
Task 1 - 12:30:30  
Skills Assessment  
Task 1 - Dism.exe  
Task 2 - Calculator.exe  
Task 3 - rundll32.exe  
Task 4 - ProcessHacker.exe  
Task 5 - No  
Task 6 - WerFault.exe  


##Introduction to Threat Hunting & Hunting With Elastic  
Threat Hunting Definition  
Task 1 - proactively and reactively  
Task 2 - false  
Task 3 - true  
The Threat Hunting Process  
Task 1 - false  
Threat Intelligence Fundamentals  
Task 1 - false  
Task 2 - Reach out to the Incident Handler/Incident Responder  
Task 3 - Provide further IOCs and TTPs associated with the incident  
Task 4 - provide insight into adversary operations  
Hunting For Stuxbot  
Task 1 - XceGuhkzaTrOy.vbs  
Task 2 - lsadump::dcsync /domain:eagle.local /all /csv, exit  
Task 3 - PowerView  
Skills Assessment  
Task 1 - svc-sql1  
Task 2 - LgvHsviAUVTsIN  
Task 3 - svc-sql1  


##Understanding Log Sources & Investigating with Splunk  
Introduction To Splunk & SPL  
Task 1 - waldo  
Task 2 - 10  
Task 3 - aparsa  
Using Splunk Applications  
Task 1 - net view /DOMAIN:uniwaldo.local  
Task 2 - 6  
Intrusion Detection With Splunk (Real-world Scenario)  
Task 1 - rundll32.exe  
Task 2 - comsvcs.dll  
Task 3 - rundll32.exe  
Task 4 - 10.0.0.186 and 10.0.0.91  
Task 5 - 3389  
Detecting Attacker Behavior With Splunk Based On TTPs  
Task 1 - Password@123  
Detecting Attacker Behavior With Splunk Based On Analytics  
Task 1 - randomfile.exe  
Skills Assessment  
Task 1 - randomfile.exe  
Task 2 - rundll32.exe  


##Windows Attacks & Defense  
Kerberoasting  
Task 1 - mariposa  
Task 2 - S-1-5-21-1518138621-4282902758-752445584-2110  
AS-REProasting  
Task 1 - shadow  
Task 2 - S-1-5-21-1518138621-4282902758-752445584-3103  
GPP Passwords  
Task 1 - abcd@123  
Task 2 - 0x80  
GPO Permissions/GPO Files  
Task 1 - DONE  
Credentials in Shares  
Task 1 - Slavi920  
Credentials in Object Properties  
Task 1 - Slavi1234  
Task 2 - No  
Task 3 - S-1-5-21-1518138621-4282902758-752445584-3102  
DCSync  
Task 1 - fcdc65703dd2b0bd789977f1f3eeaecf  
Task 2 - Directory Service Access  
Golden Ticket  
Task 1 - db0d0630064747072a7da3f7c3b4069e  
Kerberos Constrained Delegation  
Task 1 - C0nsTr@in3D_F1@G_Dc01!  
Print Spooler & NTLM Relaying  
Task 1 - d9b53b1f6d7c45a8  
Task 2 - [-] unhandled exception occured: SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.)  
Coercing Attacks & Unconstrained Delegation  
Task 1 - DONE  
Object ACLs  
Task 1 - DONE  
PKI - ESC1  
Task 1 - Pk1_Vuln3r@b!litY  
Task 2 - 12-19-2022  
Skills Assessment  
Task 1 - EAGLE\DC2$  


##Intro to Network Traffic Analysis  
Tcpdump Fundamentals  
Task 1 - 174.143.213.184  
Task 2 - relative  
Task 3 - -nvXc 100  
Task 4 - sudo tcpdump -Xr /tmp/capture.pcap  
Task 5 - -v  
Task 6 - man  
Task 7 - -w  
Capturing with tcpdump (Fundamentals Lab)  
Task 1 - -l  
Task 2 - true  
Task 3 - not icmp  
Task 4 - true  
Interrogating Network Traffic With Capture and Display Filters  
Task 1 - 80 43806  
Task 2 - 172.16.146.1  
Analysis with Wireshark  
Task 1 - true  
Task 2 - Packet List  
Task 3 - Packet Bytes  
Task 4 - -D  
Task 5 - -f  
Task 6 - before  
Wireshark Advanced Usage  
Task 1 - Statistics  
Task 2 - Analyze  
Task 3 - TCP  
Task 4 - true  
Task 5 - false  
Packet Inception, Dissecting Network Traffic With Wireshark  
Task 1 - Rise-Up.jpg  
Task 2 - bob  
Guided Lab: Traffic Analysis Workflow  
Task 1 - hacker  
Task 2 - 44  
Task 3 - 4444  
Decrypting RDP connections  
Task 1 - bucky  


##Intermediate Network Traffic Analysis  
ARP Spoofing & Abnormality Detection  
Task 1 - 507  
ARP Scanning & Denial-of-Service  
Task 1 - 2c:30:33:e2:d5:c3  
802.11 Denial of Service  
Task 1 - 14592  
Rogue Access Point & Evil-Twin Attacks  
Task 1 - 2c:6d:c1:af:eb:91  
Fragmentation Attacks  
Task 1 - 66535  
IP Source & Destination Spoofing Attacks  
Task 1 - 1  
TCP Handshake Abnormalities  
Task 1 - 429  
TCP Connection Resets & Hijacking  
Task 1 - administrator  
ICMP Tunneling  
Task 1 - This is a secure key: Key123456789  
HTTP/HTTPs Service Enumeration  
Task 1 - 204  
Strange HTTP Headers  
Task 1 - 7  
Cross-Site Scripting (XSS) & Code Injection Detection  
Task 1 - mZjQ17NLXY8ZNBbJCS0O  
SSL Renegotiation Attacks  
Task 1 - 16  
Peculiar DNS Traffic  
Task 1 - HTB{Would_you_forward_me_this_pretty_please}  
Strange Telnet & UDP Connections  
Task 1 - HTB(Ipv6_is_my_best_friend)  
Task 2 - ICMP Tunneling  


##Working with IDS/IPS  
Suricata Fundamentals  
Task 1 - 1252204100696793  
Task 2 - app.php  
Suricata Rule Development Part 1  
Task 1 - 4  
Suricata Rule Development Part 2 (Encrypted Traffic)  
Task 1 - 72a589da586844d7f0818ce684948eea  
Snort Fundamentals  
Task 1 - 234  
Snort Rule Development  
Task 1 - http_header;  
Intrusion Detection With Zeek  
Task 1 - dce_rpc.log  
Task 2 - 2311  
Skills Assessment - Suricata  
Task 1 - Create  
Skills Assessment - Snort  
Task 1 - 17  
Skills Assessment - Zeek  
Task 1 - certificate.subject  


##Introduction to Malware Analysis  
Windows Internals  
Task 1 - 5.885  
Task 2 - AttachConsole  
Static Analysis On Linux  
Task 1 - 3399c4043c56fea40a8189de302fd889  
Static Analysis On Windows  
Task 1 - BFF6A1000A86F8EDF3673D576786EC75B80BED0C458A8CA0BD52D12B74099071  
Dynamic Analysis  
Task 1 - 127.0.0.1  
Reverse Engineering & Code Analysis  
Task 1 - Software\Microsoft\Windows\CurrentVersion\Run  
Task 2 - sub_40A7A3  
Debugging  
Task 1 - FC4883E4F0E8C0000000415141  
Creating Detection Rules  
Task 1 - Done  
Skills Assessment  
Task 1 - 1c7243c8f3586b799a5f9a2e4200aa92  
Task 2 - No  
Task 3 - brbconfig.tmp  
Task 4 - brb.3dtuts.by  
Task 5 - Yes  
Task 6 - CryptDecrypt  


##JavaScript Deobfuscation  
Source Code  
Task 1 - HTB{4lw4y5_r34d_7h3_50urc3}  
Deobfuscation  
Task 1 - HTB{1_4m_7h3_53r14l_g3n3r470r!}  
HTTP Requests  
Task 1 - N2gxNV8xNV9hX3MzY3IzN19tMzU1NGcz  
Decoding  
Task 1 - HTB{ju57_4n07h3r_r4nd0m_53r14l}  
Skills Assessment  
Task 1 - api.min.js  
Task 2 - HTB{j4v45cr1p7_3num3r4710n_15_k3y}  
Task 3 - HTB{n3v3r_run_0bfu5c473d_c0d3!}  
Task 4 - 4150495f70336e5f37333537316e365f31355f66756e  
Task 5 - HTB{r34dy_70_h4ck_my_w4y_1n_2_HTB}  


##YARA & Sigma for SOC Analysts  
Developing YARA Rules  
Task 1 - TSMSISrv.dll  
Hunting Evil with YARA (Windows Edition)  
Task 1 - 53616e64626f78206465746563746564  
Hunting Evil with YARA (Linux Edition)  
Task 1 - @WanaDecryptor@  
Developing Sigma Rules  
Task 1 - mimidrv.sys  
Hunting Evil with Sigma (Chainsaw Edition)  
Task 1 - c:\document\virus\  
Hunting Evil with Sigma (Splunk Edition)  
Task 1 - C:\Users\waldo\Downloads\20221108112718_BloodHound.zip  
Skills Assessment  
Task 1 - LsaWrapper  
Task 2 - faaeba08-01f0-4a32-ba48-bd65b24afd28  


Introduction to Digital Forensics  
Evidence Acquisition Techniques & Tools  
Task 1 - AutorunsToWinEventLog  
Memory Forensics  
Task 1 - tasksche.exe  
Task 2 - hibsys.WNCRYT  
Task 3 - 3012  
Rapid Triage Examination & Analysis Tools  
Task 1 - microsoft.windowskits.feedback.exe  
Task 2 - Microsoft-Windows-DiagnosticDataCollector  
Task 3 - cmdkey.exe  
Practical Digital Forensics Scenario  
Task 1 - PowerView  
Task 2 - rundll32.exe  
Skills Assessment  
Task 1 - reverse.exe  
Task 2 - 3.19.219.4  
Task 3 - HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run  
Task 4 - C:\Users\j0seph\AppData\Local\mimik  
Task 5 - insurance.DOCX  


##Detecting Windows Attacks with Splunk  
Detecting Common User/Domain Recon  
Task 1 - rundll32  
Detecting Password Spraying  
Task 1 - sa  
Detecting Responder-like Attacks  
Task 1 - f1nancefileshare  
Detecting Kerberoasting/AS-REProasting  
Task 1 - CORP\LANDON_HINES  
Detecting Pass-the-Hash  
Task 1 - BLUE.corp.local  
Detecting Pass-the-Ticket  
Task 1 - YOUNG_WILKINSON  
Detecting Overpass-the-Hash  
Task 1 - rundll32.exe  
Detecting Golden Tickets/Silver Tickets  
Task 1 - CIFS  
Detecting Unconstrained Delegation/Constrained Delegation Attacks  
Task 1 - DC01.corp.local  
Detecting DCSync/DCShadow  
Task 1 - GC  
Detecting RDP Brute Force Attacks  
Task 1 - 192.168.152.140  
Detecting Beaconing Malware  
Task 1 - timechart  
Detecting Nmap Port Scanning  
Task 1 - Yes  
Detecting Kerberos Brute Force Attacks  
Task 1 - Yes  
Detecting Kerberoasting  
Task 1 - 88  
Detecting Golden Tickets  
Task 1 - 88  
Detecting Cobalt Strike's PSExec  
Task 1 - 192.168.38.104  
Detecting Zerologon  
Task 1 - False  
Detecting Exfiltration (HTTP)  
Task 1 - 192.168.151.181  
Detecting Exfiltration (DNS)  
Task 1 - letsgohunt.online  
Detecting Ransomware  
Task 1 - 4588  
Skills Assessment  
Task 1 - 4.680851063829787  
Task 2 - 192.168.1.149  
Task 3 - 192.168.109.105  


##Security Incident Reporting  
Introduction to Security Incident Reporting  
Task 1- phishing  
The Incident Reporting Process  
Task 1 - Incident Logging  
Elements of a Proper Incident Report  
Task 1 - Attack Vector Diagram  
