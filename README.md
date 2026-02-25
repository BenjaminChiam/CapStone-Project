# 🛡️ Cyber Security Threat Hunt Assistant

An AI-powered conversational threat hunting assistant built with **Streamlit** and **OpenAI GPT-4o**. Designed for SOC analysts to analyze IOCs, map threats to MITRE ATT&CK, detect campaigns via ML clustering, and auto-generate Sigma detection rules.

> **Capstone Project** — Automated IOC Enrichment and Threat Intel Visualization  
> Singapore Institute of Technology: University of Applied Learning

---

## ✨ Features

| Feature | Description |
|---|---|
| **💬 AI Chat Interface** | Conversational threat hunting powered by GPT-4o with a "Senior CTI Analyst" persona |
| **🔍 IOC Enrichment** | Multi-source enrichment via VirusTotal, Shodan, and AbuseIPDB APIs |
| **🎯 MITRE ATT&CK Mapping** | Automated TTP mapping with LLM reasoning + local ID validation to prevent hallucinations |
| **📊 ML Campaign Detection** | K-Means clustering with Shannon Entropy features for unsupervised DGA/botnet detection |
| **📝 Sigma Rule Generator** | One-click detection rule generation for IPs, domains, and file hashes |
| **⚖️ Consensus Scoring** | Weighted multi-source voting algorithm for IOC risk assessment |
| **📋 Investigation Log** | Exportable session history (JSON/CSV) for audit trails |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- OpenAI API key ([get one here](https://platform.openai.com/api-keys))
- Optional: VirusTotal, Shodan, AbuseIPDB API keys

### Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/threat-hunt-assistant.git
cd threat-hunt-assistant

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
# Build and run
docker build -t threat-hunt-assistant .
docker run -p 8501:8501 --env-file .env threat-hunt-assistant
```

---

## ☁️ Deploy to Streamlit Community Cloud (Free)

1. **Push your code to GitHub** (make sure `.env` is in `.gitignore`!)
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Click **New App** → select your repo → set main file as `app.py`
4. Add secrets in **Advanced Settings** → `secrets.toml`:

```toml
OPENAI_API_KEY = "sk-..."
VIRUSTOTAL_API_KEY = "..."
SHODAN_API_KEY = "..."
ABUSEIPDB_API_KEY = "..."
```

5. Click **Deploy** — your app will be live at `https://your-app.streamlit.app`

---

## 📁 Project Structure

```
threat-hunt-assistant/
├── app.py                          # Main chatbot interface
├── pages/
│   ├── 1_Cluster_Analysis.py        # ML clustering visualization
│   └── 2_Investigation_Log.py       # Session history & export
├── utils/
│   ├── __init__.py
│   ├── ioc_enrich.py               # Multi-source IOC enrichment
│   ├── mitre_mapper.py             # GPT-4o MITRE ATT&CK mapping
│   ├── mitre_data.py               # Local MITRE ID validation dictionary
│   ├── ml_engine.py                # K-Means clustering engine
│   └── sigma_generator.py          # Sigma rule auto-generation
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
┌─────────────────────────────────────────────────────┐
│                  Streamlit Frontend                   │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Chat UI  │  │ Cluster Viz  │  │ Invest. Log   │  │
│  └────┬─────┘  └──────┬───────┘  └───────────────┘  │
│       │               │                              │
├───────┼───────────────┼──────────────────────────────┤
│       ▼               ▼          Backend             │
│  ┌─────────┐   ┌────────────┐                        │
│  │ OpenAI  │   │ ML Engine  │                        │
│  │ GPT-4o  │   │ (K-Means)  │                        │
│  └────┬────┘   └────────────┘                        │
│       │                                              │
│  ┌────┴──────────────────────────────┐               │
│  │        IOC Enrichment Pipeline     │               │
│  │  VirusTotal │ Shodan │ AbuseIPDB  │               │
│  └──────────────┬────────────────────┘               │
│                 │                                     │
│  ┌──────────────┴────────────────────┐               │
│  │    Consensus Scoring Engine        │               │
│  │    MITRE Mapper + Validator        │               │
│  │    Sigma Rule Generator            │               │
│  └───────────────────────────────────┘               │
└─────────────────────────────────────────────────────┘
```

---

## 💡 Usage Examples

### Chat with the Assistant
- *"Analyze this IP: 185.243.112.55 — is it associated with any known C2 infrastructure?"*
- *"Generate a threat hunting hypothesis for DNS tunneling in our environment"*
- *"Write a Sigma rule to detect Cobalt Strike beacons on port 443"*
- *"What MITRE techniques are associated with APT29?"*

### Quick IOC Tools (Sidebar)
1. Paste an IOC in the sidebar
2. Click **🔍 Enrich** for multi-source analysis
3. Click **🎯 MITRE Map** for ATT&CK mapping
4. Click **📝 Sigma Rule** to generate and download a detection rule

---

## 🔐 Security Notes

- **Never commit API keys** — use `.env` locally or Streamlit secrets for cloud
- The MITRE mapper validates all LLM outputs against a local dictionary to prevent hallucinated technique IDs
- For production use, add authentication via Streamlit's `st.experimental_user` or a reverse proxy
- Consider Upstash Redis for production caching instead of `st.cache_data`

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [MITRE ATT&CK®](https://attack.mitre.org/) Framework
- [Streamlit](https://streamlit.io/) — App framework
- [OpenAI](https://openai.com/) — GPT-4o API
- [VirusTotal](https://www.virustotal.com/), [Shodan](https://www.shodan.io/), [AbuseIPDB](https://www.abuseipdb.com/) — Threat intelligence APIs
- [Sigma](https://github.com/SigmaHQ/sigma) — Detection rule standard
