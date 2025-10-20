# 🛡️ Windows Activity Monitor Agent

A lightweight Python-based security agent for **monitoring suspicious file executions and malicious browser activity** on Windows systems. The agent detects:

- Executable file launches (`.exe`, `.bat`, `.ps1`)
- Access to potentially malicious websites via Chrome browser history

---

## 📦 Features

- ✅ Real-time **process monitoring** using WMI
- 🌐 Scans **Google Chrome browser history** for known malicious domains
- 📄 Outputs events as structured JSON (can be extended to send to Kafka or REST APIs)
- 🔧 Fully threaded and non-blocking
- 🧠 Easily extensible with custom domain lists and event handling

---

## ⚙️ Requirements

- Python 3.7+
- Admin privileges (for WMI access)
- Google Chrome installed

### Python Packages

Install dependencies using pip:

```bash
pip install wmi


