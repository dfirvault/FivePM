# 🔍 FivePM — Advanced Threat Intelligence Scanner

**FivePM** is a modern, Streamlit-based cybersecurity tool designed to **detect and visualize threat indicators** across text and log files.  
It combines regex-based IOC detection with GeoIP enrichment, ASN lookup, and interactive dashboards — built for threat hunters, DFIR analysts, and blue teams.

---

## 🚀 Features

### 🧠 Threat Detection Engine
FivePM scans files and directories for a wide range of **Indicators of Compromise (IOCs)**, including:
- **Network Indicators**: IPv4, IPv6, domains, URLs, email addresses  
- **Cryptocurrency**: Bitcoin and Ethereum wallet addresses  
- **Malware Signatures**: Mimikatz, Metasploit, Cobalt Strike, Empire, etc.  
- **Attack Techniques**: Reverse shells, credential dumping, lateral movement  
- **Hashes & Encryption**: MD5, SHA1, SHA256, AES/XOR/RC4 keys  
- **Obfuscation & Suspicious Behavior**: Base64, certutil, encoded payloads  
- **Vulnerabilities**: CVE identifiers and suspicious command usage  

### 🌍 GeoIP Enrichment
- Automatically downloads and manages **GeoLite2-City** and **GeoLite2-ASN** databases  
- Maps suspicious IPs to **countries, cities, and organizations (ASN)**  
- Displays interactive **geo-maps** using Plotly for visual threat localization  

### 📊 Interactive Analysis
- Real-time, tabbed Streamlit dashboard:
  - **Indicators Overview**: Count and classify IOCs by type  
  - **GeoIP Visualization**: Interactive world map of source IPs  
  - **Detailed Findings**: Per-file breakdown of indicators and context lines  
  - **Statistics View**: Top matches, unique entities, and indicator distributions  

### ⚙️ Smart Data Handling
- Optimized for **large datasets** (sampling + summarization)
- Folder and file-based scanning
- Automatic database verification and recovery  
- Export results to CSV for further analysis

---

## 🖥️ Interface Preview

<img width="1899" height="894" alt="image" src="https://github.com/user-attachments/assets/cae80d4e-1452-44da-b4b9-a726ecfafa4a" />

<img width="1901" height="893" alt="image" src="https://github.com/user-attachments/assets/28541e9f-573a-49a5-8f83-622becb1f33d" />

<img width="1897" height="862" alt="image" src="https://github.com/user-attachments/assets/cbbc4ea9-af50-4680-9999-a77ca130921f" />

<img width="1889" height="852" alt="image" src="https://github.com/user-attachments/assets/a893f89d-6f60-48ec-a171-14afcc8d1169" />

<img width="1905" height="885" alt="image" src="https://github.com/user-attachments/assets/8579db4a-8e9f-42ea-b609-6f34a4c6cfe8" />

---

## 🧩 Installation

### Prerequisites
- Python **3.9+**
- `pip` package manager
- Internet access for downloading GeoLite2 databases (first-time setup)

### Clone and Setup
```bash
git clone https://github.com/dfirvault/FivePM.git
cd FivePM
pip install -r requirements.txt
```

### Run the Application
```bash
streamlit run fivepm.py
```

> On first launch, FivePM will automatically download the required GeoLite2 databases (City + ASN).

---

## 📁 Usage

1. Launch the app with `streamlit run fivepm.py`
2. Choose input method in the sidebar:
   - **Upload File** — single log or text file
   - **Select Directory** — recursively scan an entire folder
3. Click **Scan** to begin analysis
4. View results in the interactive dashboard
5. Optionally, export summaries via the **Export Results** panel

---

## 🧠 Supported IOC Categories

| Category | Examples |
|-----------|-----------|
| **Network Indicators** | IPs, domains, URLs, emails |
| **Hashes** | MD5, SHA1, SHA256 |
| **Malware & Tools** | Mimikatz, Cobalt Strike, Metasploit, Empire |
| **Credential Access** | lsass.exe, procdump, sekurlsa::logonpasswords |
| **Lateral Movement** | PsExec, WinRM, WMIExec |
| **Persistence** | schtasks, registry run keys |
| **Defense Evasion** | AMSI bypass, UAC bypass, Process hollowing |
| **Crypto & Encoding** | AES/XOR/RC4 keys, Base64 strings |
| **Vulnerabilities** | CVE-XXXX-XXXX patterns |

---

## 🗺️ GeoIP Database Notes

FivePM automatically manages and validates GeoLite2 databases:
- **City DB** — `GeoLite2-City.mmdb`
- **ASN DB** — `GeoLite2-ASN.mmdb`

If missing or corrupted, the tool will prompt you to download replacements.

---

## 🧰 Dependencies

| Library | Purpose |
|----------|----------|
| **Streamlit** | Web UI framework |
| **GeoIP2** | IP geolocation |
| **Plotly** | Interactive visualizations |
| **Pandas** | Data manipulation |
| **Requests** | HTTP downloads |
| **Logging** | Event tracking and diagnostics |

Install all dependencies via:
```bash
pip install -r requirements.txt
```

Example `requirements.txt`:
```
streamlit
geoip2
plotly
pandas
requests
```

---

## 🔒 Security Notice

- FivePM uses **local scanning** — your data never leaves your machine.  
- The GeoLite2 databases are fetched directly from a **public GitHub mirror**.  
- No cloud APIs or telemetry are used.  

---

## 🧑‍💻 Author

**Jacob Wilson**  
Cybersecurity Investigator & Threat Researcher  
📍 Australia  

---

## 🪪 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## ⭐ Contribute

Pull requests and feature suggestions are welcome!  
Some planned features:
- 🔥 Integration with VirusTotal / AbuseIPDB lookups  
- 🧮 Machine learning–based IOC clustering  
- 🌐 Web dashboard deployment via Docker  

---

> 💡 *FivePM helps analysts rapidly detect, enrich, and visualize indicators of compromise — turning raw logs into actionable intelligence.*
