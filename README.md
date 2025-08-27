# Endpoint Security & Threat Intelligence  

## 📌 Project Overview  
This project focuses on strengthening endpoint devices by implementing *endpoint security solutions* and leveraging *threat intelligence feeds* to detect and mitigate cyber threats.  
The objective was to secure endpoints, monitor suspicious activity, and enhance detection with external threat intelligence.  

---

## 🚀 Tools & Technologies  
- *Wazuh Agent* → For endpoint monitoring (Windows & Linux)  
- *OSSEC / Sysmon* → For detailed process & event logging  
- *VirusTotal / AlienVault OTX* → Threat intelligence feeds  
- *Windows 10 / Ubuntu* → Endpoints for deployment & testing  

---

## 🔧 Implementation Steps  
1. *Endpoint Agent Deployment*  
   - Installed Wazuh agent on Windows and Ubuntu endpoints  
   - Configured agents to send logs to the Wazuh manager  

2. *Log Collection & Monitoring*  
   - Enabled process monitoring, registry monitoring, and file integrity monitoring (FIM)  
   - Collected Windows Event Logs and Linux Syslogs  

3. *Threat Intelligence Integration*  
   - Integrated *OTX (Open Threat Exchange)* with Wazuh  
   - Configured Wazuh to match logs with known IoCs (Indicators of Compromise)  
   - Used VirusTotal API for file hash reputation checks  

4. *Testing & Validation*  
   - Executed simulated malware samples and suspicious scripts  
   - Verified that endpoint activities were detected and alerts generated  
   - Checked Wazuh dashboard for threat intelligence correlation  

---

## 📊 Results  
- Endpoints were successfully monitored for suspicious activity  
- Wazuh agents detected unauthorized changes in real-time  
- Threat intelligence feeds helped identify known malicious IPs/domains  
- Alerts were centralized in the SIEM dashboard  

---

## 📂 Repository Structure
