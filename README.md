# 🛡️ Splunk SOC Detection Lab

End-to-end SOC detection lab using **Windows Event Logs (Event ID 4688)**, **Sysmon**, and **Splunk** to detect **LOLBins** mapped to the **MITRE ATT&CK framework**.

---

## 🛡️ Objective

This lab demonstrates a **real-world SOC detection pipeline**, from Windows telemetry generation to SIEM-based detection and investigation.

Key objectives:

- Monitor Windows process creation (**Event ID 4688**)
- Enrich telemetry with **Sysmon**
- Detect **Living-off-the-Land Binaries (LOLBins)**
- Perform **command-line and parent–child analysis**
- Map detections to **MITRE ATT&CK**
- Build analyst-ready Splunk searches

---

## 🛡️ SOC Architecture

![SOC Architecture](architecture/soc-architecture.png)

**Description**

This diagram illustrates the end-to-end SOC detection architecture used in this lab.

Windows endpoints generate **Security Event Logs (4688)** and **Sysmon telemetry**, which are collected by the **Splunk Universal Forwarder** and forwarded to **Splunk Enterprise** for detection, investigation, and MITRE ATT&CK mapping.

---

## 🔍 Data Sources

- Windows Security Event Logs (Event ID 4688)
- Sysmon (Process Create, Command Line)
- Splunk Universal Forwarder

---

## 🧪 Detection Use Cases

The following techniques and LOLBins are monitored:

- PowerShell abuse
- Rundll32 LOLBin execution
- Regsvr32 abuse
- Mshta command execution
- Certutil file download abuse
- WMI and script interpreter abuse

---

## 🧪 Detection Walkthrough (Step-by-Step)

### 1️⃣ Architecture Overview  
**Screenshot:** 

![SOC Architecture](architecture/soc-architecture.png)  

High-level view of the SOC pipeline from endpoint to SIEM.

---

### 2️⃣ Sysmon Installed and Running  
**Screenshot:**:- 

![Alt text](screenshots/02-sysmon-installed.png)

Confirms Sysmon is installed and actively generating enhanced telemetry.

---

### 3️⃣ Splunk Universal Forwarder Running  
**Screenshot:** 

![Alt text](screenshots/03-splunk-forwarder-running.png)
  
Validates log forwarding from the Windows endpoint to Splunk.

---

### 4️⃣ Event ID 4688 Ingested  
**Screenshot:**

![Alt text](screenshots/04-event-4688-ingested.png)  

Shows raw Windows process creation events successfully indexed.

---

### 5️⃣ Sysmon Process Creation Events  
**Screenshot:** 

![Alt text](screenshots/05-sysmon-process-create.png)  

Displays enriched process telemetry including image paths and command lines.

---

### 6️⃣ Command-Line Fields Extracted  
**Screenshot:**

![Alt text](screenshots/06-commandline-fields-extracted.png)  

Extracted fields include:
- `NewProcessName`
- `CommandLine`
- `ParentProcessName`

---

### 7️⃣ LOLBin Detection – Rundll32  
**Screenshot:** 

![Alt text](screenshots/07-lolbin-rundll32-detection.png)

Identifies Rundll32 executions consistent with LOLBin activity.

---

### 8️⃣ Command-Line Analysis  
**Screenshot:** 

![Alt text](screenshots/08-commandline-analysis.png)

Analyzes suspicious command-line arguments associated with LOLBins.

---

### 9️⃣ Parent–Child Process Analysis  
**Screenshot:** 

![Alt text](screenshots/09-parent-child-analysis.png)

Visualizes abnormal parent–child process relationships.

---

### 🔟 MITRE ATT&CK Mapping  
**Screenshot:** 

![Alt text](screenshots/10-mitre-attack-mapping.png)  

Detected activity mapped to MITRE ATT&CK techniques, including:

- **T1059.001 – PowerShell**
- **T1218.011 – Rundll32**
- **T1218.010 – Regsvr32**

---

## 📊 Detection Logic

- Event ID 4688 process creation monitoring
- Command-line inspection
- Parent–child process relationship analysis
- LOLBins allow/deny logic
- MITRE ATT&CK technique tagging

---

## 🛠 Tools Used

- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon
- Windows Event Logging
- Sigma Rules
- MITRE ATT&CK Framework

---

## 📁 Repository Structure

```text
splunk-soc-detection-lab/
├── architecture/
│   └── soc-architecture.png
├── screenshots/
│   ├── 01-architecture-overview.png
│   ├── 02-sysmon-installed.png
│   ├── 03-splunk-forwarder-running.png
│   ├── 04-event-4688-ingested.png
│   ├── 05-sysmon-process-create.png
│   ├── 06-commandline-fields-extracted.png
│   ├── 07-lolbin-rundll32-detection.png
│   ├── 08-commandline-analysis.png
│   ├── 09-parent-child-analysis.png
│   └── 10-mitre-attack-mapping.png
├── spl/
├── sigma/
└── README.md
