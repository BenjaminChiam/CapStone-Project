# 🧠 CognitiveHunt — AI-Enhanced Threat Intelligence Platform

An AI-powered threat hunting and IOC analysis platform built with **Streamlit**, **OpenAI GPT-4o**, and **scikit-learn**. Designed for SOC analysts to automate IOC enrichment, detect threat campaigns via unsupervised ML, map adversary behaviors to MITRE ATT&CK, analyze raw security logs, and generate detection rules — all through a conversational interface.

> **Capstone Project** — Automated IOC Enrichment and Threat Intel Visualization  
> Singapore Institute of Technology: University of Applied Learning · 2025–2026

---

## ✨ Features

### 💬 AI Chatbot (HuntBot)
| Feature | Description |
|---|---|
| **Conversational Threat Hunting** | GPT-4o powered assistant with a "Senior CTI Analyst" persona |
| **P1–P4 Triaging System** | Structured severity classification with immediate actions, investigation steps, escalation criteria, and containment recommendations |
| **Environment-Aware Responses** | Tailors SIEM queries (SPL, KQL, EQL) and tool recommendations to the analyst's configured security stack |
| **Detection Rule Drafting** | Generates Sigma, YARA, and SIEM-native queries on demand |

### 🔍 IOC Enrichment (7 Sources)
| Source | Intelligence |
|---|---|
| **VirusTotal** | File/IP/domain/URL reputation and detection ratios |
| **Shodan** | Open ports, banners, ASN, vulnerabilities, SSL/JARM fingerprints |
| **AbuseIPDB** | IP abuse reports, confidence scoring, Tor exit node detection |
| **GreyNoise** | Internet noise vs. targeted attack classification |
| **URLhaus** | Malicious URL database (abuse.ch) |
| **MalwareBazaar** | Malware sample lookup by hash (abuse.ch) |
| **WHOIS** | Domain registration age, registrar, and ownership data |

### 🤖 Machine Learning (5 Engines)
| Engine | Purpose |
|---|---|
| **K-Means Clustering** | Campaign detection using Shannon Entropy, digit ratio, vowel ratio, subdomain depth |
| **DBSCAN** | Density-based clustering for identifying threat groups without specifying K |
| **Isolation Forest** | Anomaly detection for zero-day and novel threat identification |
| **TF-IDF Cosine Similarity** | IOC correlation based on shared behavioral tags and descriptions |
| **DGA Detector** | Domain Generation Algorithm scoring using entropy + English bigram analysis |

### 🎯 MITRE ATT&CK Integration
| Feature | Description |
|---|---|
| **ATT&CK Matrix Heatmap** | Navigator-style visualization with group coverage overlay |
| **Technique Explorer** | Deep-dive into any technique — sub-techniques, groups, software, mitigations, data sources |
| **Group Analysis** | Radar charts for kill chain coverage, APT group comparison tool |
| **Detection Coverage Tracker** | Track which techniques your SOC detects, visualize gaps per tactic |
| **Relationship Graph** | Interactive network graph of Technique ↔ Group ↔ Software ↔ Mitigation relationships |
| **LLM-Powered Mapping** | GPT-4o maps IOCs to TTPs with reasoning, validated against 400+ local technique IDs |

### 📂 Log File Analysis (11 Log Types)
| Log Type | Format | Key Analysis |
|---|---|---|
| **FortiGate UTM** | Key=value | Web filter, app control, src/dst IP, URL categories |
| **FortiGate Event** | Key=value | System events, DHCP statistics, VPN |
| **IIS Web Server** | W3C space-delimited | HTTP method, URI, status code, user-agent, client IP |
| **Nessus Scan** | JSON | Vulnerability severity, plugin families, affected hosts |
| **HTTP Stream** | JSON | Full HTTP request/response, headers, content |
| **ICMP Stream** | JSON | Ping sweeps, echo request/reply patterns |
| **MAPI Stream** | JSON | Email protocol traffic, attachment indicators |
| **DHCP Stream** | JSON | Lease activity, rogue device detection |
| **Windows Registry** | Multiline KV | Process image, key path, registry operations |
| **WinEventLog Application** | Multiline KV | Application events, source names, event codes |
| **WinEventLog System** | Multiline KV | Service installations, SCM events, system errors |

Log analysis includes: auto-detection, IOC extraction, 44 MITRE ATT&CK detection rules, timeline visualization with spike detection, top-talker analysis, and ML anomaly detection.

### 📝 Additional Capabilities
| Feature | Description |
|---|---|
| **Sigma Rule Generator** | Auto-generates valid .yml detection rules for IPs, domains, and file hashes |
| **Consensus Scoring** | Weighted multi-source voting algorithm (7 sources) for IOC risk assessment |
| **Environment Profiler** | Configure SIEM, EDR, firewall, cloud, OS, log sources, compliance frameworks |
| **Investigation Log** | Full session history with search, JSON/CSV export for audit trails |
| **IOC Export** | Extract and export IOCs from uploaded logs as JSON |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- OpenAI API key ([get one here](https://platform.openai.com/api-keys))
- Optional: VirusTotal, Shodan, AbuseIPDB, GreyNoise API keys

### Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/BenjaminChiam/CapStone-Project.git
cd CapStone-Project

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
cp .env.example .env
# Edit .env with your API keys

# 5. Run the app
streamlit run app.py
```

The app will open at `http://localhost:8501`.

### Docker Setup

```bash
docker build -t cognitivehunt .
docker run -p 8501:8501 --env-file .env cognitivehunt
```

---

## ☁️ Deploy to Streamlit Community Cloud

1. Push your code to GitHub (ensure `.env` is in `.gitignore`)
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Click **New App** → select your repo → set main file as `app.py`
4. Add secrets in **Advanced Settings** → `secrets.toml`:

```toml
OPENAI_API_KEY = "sk-..."
VIRUSTOTAL_API_KEY = "..."
SHODAN_API_KEY = "..."
ABUSEIPDB_API_KEY = "..."
GREYNOISE_API_KEY = "..."
```

5. Click **Deploy**

---

## 📁 Project Structure

```
CapStone-Project/
├── app.py                          # Main chatbot interface (CognitiveHunt)
├── pages/
│   ├── 1_Cluster_Analysis.py       # ML clustering, anomaly detection, DGA scanner
│   ├── 2_Investigation_Log.py      # Log upload, analysis, IOC extraction, MITRE mapping
│   ├── 3_Environment_Profile.py    # Corporate environment configuration
│   └── 4_MITRE ATT&CK.py          # ATT&CK Navigator, group analysis, coverage tracker
├── utils/
│   ├── __init__.py
│   ├── ioc_enrich.py               # 7-source IOC enrichment pipeline
│   ├── log_analyzer.py             # Log parsers, IOC extraction, 44 MITRE detection rules
│   ├── mitre_attack_data.py        # ATT&CK data: 14 tactics, 120+ techniques, 10 APTs, 10 tools
│   ├── mitre_data.py               # Local MITRE technique ID validation dictionary (400+)
│   ├── mitre_mapper.py             # GPT-4o MITRE mapping with hallucination guard
│   ├── ml_engine.py                # 5 ML engines: K-Means, DBSCAN, Isolation Forest, TF-IDF, DGA
│   └── sigma_generator.py          # Sigma rule auto-generation (IP/domain/hash templates)
├── .streamlit/
│   └── config.toml                 # Streamlit theme (SOC dark mode)
├── requirements.txt
├── Dockerfile
├── .env.example
├── .gitignore
└── README.md
```

---

## 🧠 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     Streamlit Frontend                            │
│  ┌──────────┐ ┌───────────┐ ┌────────────┐ ┌──────────────────┐ │
│  │ Chatbot  │ │ ML Cluster│ │ Invest.Log │ │ MITRE Navigator  │ │
│  │ (GPT-4o) │ │ & Anomaly │ │ & Log      │ │ & Coverage       │ │
│  │          │ │ Detection │ │ Analyzer   │ │ Tracker          │ │
│  └────┬─────┘ └─────┬─────┘ └─────┬──────┘ └────────┬─────────┘ │
│       │             │             │                  │            │
├───────┼─────────────┼─────────────┼──────────────────┼────────────┤
│       ▼             ▼             ▼                  ▼   Backend  │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────────┐ │
│  │ OpenAI  │  │ ML Engine│  │ Log      │  │ MITRE ATT&CK       │ │
│  │ GPT-4o  │  │ (5 algo) │  │ Parsers  │  │ Data Model         │ │
│  └────┬────┘  └──────────┘  │ (11 types│  │ (14 Tactics,       │ │
│       │                     └──────────┘  │  120+ Techniques,   │ │
│  ┌────┴──────────────────────────────┐    │  10 APT Groups,     │ │
│  │    IOC Enrichment Pipeline (x7)   │    │  10 Software)       │ │
│  │  VT│Shodan│AbuseIPDB│GreyNoise   │    └────────────────────┘ │
│  │  URLhaus│MalwareBazaar│WHOIS      │                           │
│  └──────────────┬────────────────────┘                           │
│                 │                                                 │
│  ┌──────────────┴──────────────────────────────────────────┐     │
│  │  Consensus Scoring │ MITRE Mapper │ Sigma Generator     │     │
│  │  Hallucination Guard │ Triaging Engine │ Env Profiler   │     │
│  └─────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
```

---

## 💡 Usage Examples

### Chatbot
- *"Analyze this IP: 185.243.112.55 — is it associated with any known C2 infrastructure?"*
- *"Generate a threat hunting hypothesis for DNS tunneling in our environment"*
- *"Write a Sigma rule to detect Cobalt Strike beacons on port 443"*
- *"What MITRE techniques are associated with APT29?"*
- *"Triage this alert: multiple failed logins from 10.0.0.50 followed by a successful login at 3am"*

### Quick IOC Tools (Sidebar)
1. Paste an IOC → Click **🔍 Enrich** for 7-source analysis
2. Click **🎯 MITRE** for ATT&CK mapping with LLM reasoning
3. Click **📝 Sigma** to generate and download a detection rule
4. Click **🧬 DGA** for Domain Generation Algorithm analysis
5. Click **🚨 Triage** for structured P1–P4 incident response guidance

### Log Analysis
1. Navigate to **Investigation Log** → **Log File Analysis** tab
2. Upload `.csv`, `.csv.gz`, `.json`, or `.log` files
3. View auto-detected log type, parsed data, and top-talker charts
4. Check **MITRE Mapping** tab for detected adversary techniques with evidence
5. Check **Anomaly Detection** tab for ML-flagged suspicious IPs and DGA domains
6. Export extracted IOCs as JSON for further investigation

---

## 🔐 Security Notes

- **Never commit API keys** — use `.env` locally or Streamlit secrets for cloud deployment
- The MITRE mapper validates all LLM outputs against a local dictionary of 400+ technique IDs to prevent hallucinated technique IDs
- URLhaus and MalwareBazaar enrichment sources require no API keys (free public APIs)
- For production use, consider adding authentication and Upstash Redis for caching

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [MITRE ATT&CK](https://attack.mitre.org/) — Adversarial Tactics, Techniques, and Common Knowledge framework
- [MITRE ATT&CK Data Model](https://github.com/mitre-attack/attack-data-model) — Schema reference for ATT&CK data structures
- [Streamlit](https://streamlit.io/) — Application framework
- [OpenAI](https://openai.com/) — GPT-4o API for LLM-powered analysis
- [VirusTotal](https://www.virustotal.com/), [Shodan](https://www.shodan.io/), [AbuseIPDB](https://www.abuseipdb.com/), [GreyNoise](https://www.greynoise.io/) — Threat intelligence APIs
- [abuse.ch](https://abuse.ch/) — URLhaus and MalwareBazaar malware databases
- [Sigma](https://github.com/SigmaHQ/sigma) — Open standard for detection rules
- [Splunk BOTSv1](https://github.com/splunk/botsv1) — Sample log dataset used for testing
