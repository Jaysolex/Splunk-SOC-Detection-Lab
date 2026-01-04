# Splunk SOC Detection Lab

End-to-end SOC detection lab using **Windows Event Logs (4688)**, **Sysmon**, and **Splunk** to detect **LOLBins** mapped to **MITRE ATT&CK**.

---

## 🧱 SOC Architecture

![SOC Architecture](architecture/soc-architecture.png)

**Description**  

This diagram shows the end-to-end SOC detection pipeline used in this lab.  
Windows endpoints generate Security Event Logs (4688) and Sysmon telemetry, which are forwarded via the Splunk Universal Forwarder to Splunk Enterprise for detection, investigation, and MITRE ATT&CK mapping.

---

## 🎯 Objective

This lab demonstrates a real-world **SOC detection pipeline**, from Windows telemetry generation to SIEM-based detection and investigation.

The focus is on:
- Process Creation monitoring (Event ID 4688)
- Sysmon telemetry enrichment
- LOLBins threat detection
- MITRE ATT&CK technique mapping
- Analyst-ready Splunk searches and dashboards

---

## 🔍 Data Sources

- Windows Security Event Logs (4688)
- Sysmon (Process Create, Command Line)
- Splunk Universal Forwarder

---

## 🧪 Detection Use Cases

- PowerShell abuse
- Rundll32 LOLBin execution
- Mshta command execution
- Certutil file download abuse
- WMI and script interpreter abuse

---

## 🛠 Tools Used

- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon
- Windows Event Logging
- Sigma Rules
- MITRE ATT&CK Framework

---

## 📊 Detection Logic

- Event ID 4688 process creation monitoring
- Command-line inspection
- Parent–child process analysis
- LOLBins allow/deny logic
- ATT&CK technique tagging

---

## 📁 Repository Structure

```text
splunk-soc-detection-lab/
├── architecture/
│   └── soc-architecture.png
├── screenshots/
├── spl/
├── sigma/
└── README.md
