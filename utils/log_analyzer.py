"""
Log Analysis Utilities — Enhanced for BOTSv1 Full Dataset
=========================================================
Supported log types:
1. FortiGate UTM          (fgt_utm)       — Firewall web filter, app control
2. FortiGate Event        (fgt_event)     — System events, DHCP, VPN
3. IIS Web Server         (iis)           — W3C format HTTP access logs
4. Nessus Vulnerability   (nessus:scan)   — Vuln scan results (JSON)
5. Stream HTTP            (stream:http)   — Full HTTP request/response capture
6. Stream ICMP            (stream:icmp)   — ICMP ping/sweep traffic
7. Stream MAPI            (stream:mapi)   — Email protocol traffic
8. Stream DHCP            (stream:dhcp)   — DHCP lease activity
9. Windows Registry       (WinRegistry)   — Registry key changes
10. WinEventLog Application               — App event log (multiline)
11. WinEventLog System                    — System event log (multiline)

Plus: Sysmon, generic CSV, network flow, any structured log format.
"""

import re
import json
import gzip
import io
import math
from collections import Counter
from typing import List, Dict, Optional
import pandas as pd
import numpy as np


# ════════════════════════════════════════════════════════════════════
# LOG TYPE DETECTION
# ════════════════════════════════════════════════════════════════════
def detect_log_type(df: pd.DataFrame) -> str:
    """Auto-detect log type from sourcetype or source column."""
    cols = set(df.columns)

    if "sourcetype" in cols and len(df) > 0:
        st = str(df["sourcetype"].iloc[0]).lower().strip()
        type_map = {
            "fgt_utm": "fortigate_utm",
            "fgt_event": "fortigate_event",
            "iis": "iis",
            "nessus:scan": "nessus_scan",
            "stream:http": "stream_http",
            "stream:icmp": "stream_icmp",
            "stream:mapi": "stream_mapi",
            "stream:dhcp": "stream_dhcp",
            "stream:dns": "stream_dns",
            "stream:tcp": "stream_tcp",
            "stream:udp": "stream_udp",
            "wineventlog:application": "wineventlog_app",
            "wineventlog:system": "wineventlog_sys",
            "wineventlog:security": "wineventlog_sec",
            "xmlwineventlog:microsoft-windows-sysmon/operational": "sysmon",
            "winregistry": "winregistry",
        }
        for key, val in type_map.items():
            if key in st:
                return val

    if "source" in cols and len(df) > 0:
        src = str(df["source"].iloc[0])
        if "WinRegistry" in src:
            return "winregistry"
        if "WinEventLog:Application" in src:
            return "wineventlog_app"
        if "WinEventLog:System" in src:
            return "wineventlog_sys"
        if "WinEventLog:Security" in src:
            return "wineventlog_sec"
        if "Sysmon" in src or "sysmon" in src:
            return "sysmon"

    if {"src_ip", "dest_ip", "src_port", "dest_port"}.issubset(cols):
        return "network_flow"

    return "generic"


LOG_TYPE_LABELS = {
    "fortigate_utm": "🔥 FortiGate UTM (Web Filter / App Control)",
    "fortigate_event": "🔥 FortiGate Event (System / VPN / DHCP)",
    "iis": "🌐 IIS Web Server Access Log",
    "nessus_scan": "🔍 Nessus Vulnerability Scan",
    "stream_http": "🌍 HTTP Stream (Full Request/Response)",
    "stream_icmp": "📡 ICMP Network Stream",
    "stream_mapi": "📧 MAPI Email Stream",
    "stream_dhcp": "📋 DHCP Lease Stream",
    "stream_dns": "🔤 DNS Stream",
    "stream_tcp": "📡 TCP Stream",
    "winregistry": "🪟 Windows Registry Changes",
    "wineventlog_app": "📝 Windows Event Log (Application)",
    "wineventlog_sys": "📝 Windows Event Log (System)",
    "wineventlog_sec": "🔐 Windows Event Log (Security)",
    "sysmon": "🔬 Sysmon Operational Log",
    "network_flow": "📡 Network Flow",
    "generic": "📄 Generic CSV / Log",
}


# ════════════════════════════════════════════════════════════════════
# FILE LOADING
# ════════════════════════════════════════════════════════════════════
def load_log_file(uploaded_file) -> pd.DataFrame:
    filename = uploaded_file.name.lower()
    content = uploaded_file.read()
    try:
        if filename.endswith(".gz"):
            decompressed = gzip.decompress(content)
            df = pd.read_csv(io.BytesIO(decompressed), low_memory=False, on_bad_lines="skip")
        elif filename.endswith(".csv"):
            df = pd.read_csv(io.BytesIO(content), low_memory=False, on_bad_lines="skip")
        elif filename.endswith((".json", ".jsonl")):
            lines = content.decode("utf-8", errors="ignore").strip().split("\n")
            records = [json.loads(l) for l in lines if l.strip()]
            df = pd.DataFrame(records)
        else:
            try:
                df = pd.read_csv(io.BytesIO(content), low_memory=False, on_bad_lines="skip")
            except Exception:
                lines = content.decode("utf-8", errors="ignore").strip().split("\n")
                df = pd.DataFrame({"_raw": lines, "_time": range(len(lines))})
        return df
    except Exception as e:
        return pd.DataFrame({"error": [str(e)]})


# ════════════════════════════════════════════════════════════════════
# PARSERS
# ════════════════════════════════════════════════════════════════════
def parse_raw_field(df: pd.DataFrame, log_type: str) -> pd.DataFrame:
    if "_raw" not in df.columns:
        return df

    parser_map = {
        "fortigate_utm": _parse_kv_logs,
        "fortigate_event": _parse_kv_logs,
        "iis": _parse_iis,
        "nessus_scan": _parse_json_stream,
        "stream_http": _parse_json_stream,
        "stream_icmp": _parse_json_stream,
        "stream_mapi": _parse_json_stream,
        "stream_dhcp": _parse_json_stream,
        "stream_dns": _parse_json_stream,
        "stream_tcp": _parse_json_stream,
        "winregistry": _parse_multiline_kv,
        "wineventlog_app": _parse_multiline_kv,
        "wineventlog_sys": _parse_multiline_kv,
        "wineventlog_sec": _parse_multiline_kv,
        "sysmon": _parse_multiline_kv,
    }
    parser = parser_map.get(log_type, lambda df: df)

    max_rows = min(len(df), 50000)
    return parser(df.head(max_rows))


def _parse_kv_logs(df: pd.DataFrame) -> pd.DataFrame:
    """Parse FortiGate-style key=value (with optional quoted values)."""
    parsed = []
    for _, row in df.iterrows():
        raw = str(row.get("_raw", ""))
        rec = {"_time": row.get("_time", ""), "host": row.get("host", "")}
        pairs = re.findall(r'(\w+)=(?:"([^"]*)"|([\S]*))', raw)
        for k, qv, pv in pairs:
            rec[k] = qv if qv else pv
        parsed.append(rec)
    return pd.DataFrame(parsed)


def _parse_json_stream(df: pd.DataFrame) -> pd.DataFrame:
    """Parse JSON-formatted stream logs (HTTP, ICMP, MAPI, DHCP, Nessus)."""
    parsed = []
    for _, row in df.iterrows():
        raw = str(row.get("_raw", ""))
        rec = {"_time": row.get("_time", ""), "host": row.get("host", "")}
        try:
            cleaned = raw.replace('""', '"').strip()
            if cleaned.startswith('"'):
                cleaned = cleaned[1:]
            if cleaned.endswith('"'):
                cleaned = cleaned[:-1]
            # Handle leading whitespace (nessus)
            cleaned = cleaned.strip()
            data = json.loads(cleaned)
            rec.update(data)
        except (json.JSONDecodeError, Exception):
            rec["_raw"] = raw
        parsed.append(rec)
    return pd.DataFrame(parsed)


def _parse_iis(df: pd.DataFrame) -> pd.DataFrame:
    """Parse IIS W3C space-delimited format."""
    # IIS fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port
    #             cs-username c-ip cs(User-Agent) cs(Referer) sc-status
    #             sc-substatus sc-win32-status time-taken
    iis_cols = [
        "date", "time", "s_ip", "cs_method", "cs_uri_stem", "cs_uri_query",
        "s_port", "cs_username", "c_ip", "cs_user_agent", "cs_referer",
        "sc_status", "sc_substatus", "sc_win32_status", "time_taken"
    ]
    parsed = []
    for _, row in df.iterrows():
        raw = str(row.get("_raw", ""))
        rec = {"_time": row.get("_time", ""), "host": row.get("host", "")}
        parts = raw.split()
        for i, col in enumerate(iis_cols):
            if i < len(parts):
                rec[col] = parts[i]
        # Map to standard column names for top-talker analysis
        rec["srcip"] = rec.get("c_ip", "")
        rec["dstip"] = rec.get("s_ip", "")
        rec["dstport"] = rec.get("s_port", "")
        rec["action"] = rec.get("sc_status", "")
        rec["hostname"] = rec.get("cs_uri_stem", "")
        parsed.append(rec)
    return pd.DataFrame(parsed)


def _parse_multiline_kv(df: pd.DataFrame) -> pd.DataFrame:
    """Parse Windows Event Log / Registry multiline key=value format."""
    parsed = []
    for _, row in df.iterrows():
        raw = str(row.get("_raw", ""))
        rec = {"_time": row.get("_time", ""), "host": row.get("host", "")}
        # Extract key=value pairs (quoted and unquoted)
        pairs = re.findall(r'(\w+)="([^"]*)"', raw)
        for k, v in pairs:
            rec[k] = v
        # Also capture Key=Value without quotes (newline separated)
        for line in raw.split("\n"):
            line = line.strip()
            m = re.match(r'^(\w+)=(.+)$', line)
            if m and m.group(1) not in rec:
                rec[m.group(1)] = m.group(2).strip('"')
        parsed.append(rec)
    return pd.DataFrame(parsed)


# ════════════════════════════════════════════════════════════════════
# IOC EXTRACTION
# ════════════════════════════════════════════════════════════════════
_PRIVATE_RANGES = [
    re.compile(r"^10\."), re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
    re.compile(r"^192\.168\."), re.compile(r"^127\."), re.compile(r"^0\."),
    re.compile(r"^255\."), re.compile(r"^224\."),
]

def is_private_ip(ip: str) -> bool:
    return any(r.match(ip) for r in _PRIVATE_RANGES)


def extract_iocs_from_df(df: pd.DataFrame) -> Dict[str, List[str]]:
    # Limit text scanning for performance
    sample = df.head(30000)
    all_text = " ".join(sample.astype(str).values.flatten())

    ips = set(re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", all_text))
    public_ips = sorted({ip for ip in ips if not is_private_ip(ip)})[:100]
    private_ips = sorted({ip for ip in ips if is_private_ip(ip)})[:50]

    domains = set(re.findall(
        r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b", all_text
    ))
    domains = sorted({d for d in domains if not re.match(r"^\d+\.\d+\.\d+\.\d+$", d) and len(d) > 4})[:100]

    md5s = sorted(set(re.findall(r"\b([a-fA-F0-9]{32})\b", all_text)))[:50]
    sha1s = sorted(set(re.findall(r"\b([a-fA-F0-9]{40})\b", all_text)))[:50]
    sha256s = sorted(set(re.findall(r"\b([a-fA-F0-9]{64})\b", all_text)))[:50]
    urls = sorted(set(re.findall(r"(https?://[^\s\"',;]+)", all_text)))[:50]

    return {
        "public_ips": public_ips, "private_ips": private_ips,
        "domains": domains, "md5_hashes": md5s,
        "sha1_hashes": sha1s, "sha256_hashes": sha256s, "urls": urls,
    }


# ════════════════════════════════════════════════════════════════════
# MITRE ATT&CK AUTO-MAPPING FROM LOG PATTERNS
# ════════════════════════════════════════════════════════════════════
MITRE_LOG_RULES = [
    # ── Registry Persistence ────────────────────────────────────
    {"pattern": r"(Run|RunOnce|CurrentVersion\\Run)", "technique": "T1547.001",
     "name": "Registry Run Keys / Startup Folder", "tactic": "Persistence",
     "confidence": "HIGH", "log_types": ["winregistry", "sysmon", "wineventlog_sec"],
     "description": "Registry autostart key modification detected."},
    {"pattern": r"(Services\\|CurrentControlSet\\Services)", "technique": "T1543.003",
     "name": "Windows Service", "tactic": "Persistence", "confidence": "MEDIUM",
     "log_types": ["winregistry", "sysmon", "wineventlog_sys"],
     "description": "Windows service registry modification detected."},
    {"pattern": r"(AppInit_DLLs|Image File Execution|Winlogon\\)", "technique": "T1546",
     "name": "Event Triggered Execution", "tactic": "Persistence", "confidence": "HIGH",
     "log_types": ["winregistry"],
     "description": "Event-triggered execution registry key modified."},

    # ── Execution ───────────────────────────────────────────────
    {"pattern": r"(powershell|pwsh)", "technique": "T1059.001",
     "name": "PowerShell", "tactic": "Execution", "confidence": "MEDIUM",
     "description": "PowerShell execution detected."},
    {"pattern": r"(cmd\.exe|command\.com)", "technique": "T1059.003",
     "name": "Windows Command Shell", "tactic": "Execution", "confidence": "LOW",
     "description": "Command shell execution detected."},
    {"pattern": r"(wscript|cscript|\.vbs|\.vbe)", "technique": "T1059.005",
     "name": "Visual Basic", "tactic": "Execution", "confidence": "MEDIUM",
     "description": "VBScript execution detected."},
    {"pattern": r"(python|\.py\b)", "technique": "T1059.006",
     "name": "Python", "tactic": "Execution", "confidence": "LOW",
     "description": "Python execution detected."},
    {"pattern": r"(rundll32)", "technique": "T1218.011",
     "name": "Rundll32", "tactic": "Defense Evasion", "confidence": "MEDIUM",
     "description": "Rundll32 proxy execution detected."},
    {"pattern": r"(mshta|mshta\.exe)", "technique": "T1218.005",
     "name": "Mshta", "tactic": "Defense Evasion", "confidence": "HIGH",
     "description": "Mshta.exe abuse detected."},
    {"pattern": r"(schtasks|at\.exe|taskschd)", "technique": "T1053.005",
     "name": "Scheduled Task", "tactic": "Execution", "confidence": "MEDIUM",
     "description": "Scheduled task creation/modification detected."},

    # ── Credential Access ───────────────────────────────────────
    {"pattern": r"(lsass|mimikatz|sekurlsa|wce\.exe|procdump.*lsass)", "technique": "T1003.001",
     "name": "LSASS Memory", "tactic": "Credential Access", "confidence": "CRITICAL",
     "description": "LSASS credential dumping activity detected."},
    {"pattern": r"(ntds\.dit|ntdsutil|secretsdump)", "technique": "T1003.003",
     "name": "NTDS", "tactic": "Credential Access", "confidence": "CRITICAL",
     "description": "Active Directory database access detected."},
    {"pattern": r"(dcsync|drsuapi|DsGetNCChanges)", "technique": "T1003.006",
     "name": "DCSync", "tactic": "Credential Access", "confidence": "CRITICAL",
     "description": "DCSync replication attack detected."},

    # ── Discovery ───────────────────────────────────────────────
    {"pattern": r"(net\s+(user|group|localgroup|share|view))", "technique": "T1087",
     "name": "Account Discovery", "tactic": "Discovery", "confidence": "MEDIUM",
     "description": "Account/network enumeration command detected."},
    {"pattern": r"(whoami|systeminfo|ipconfig|hostname)", "technique": "T1082",
     "name": "System Information Discovery", "tactic": "Discovery", "confidence": "LOW",
     "description": "System information gathering detected."},
    {"pattern": r"(nltest|dsquery|adfind|ldapsearch)", "technique": "T1482",
     "name": "Domain Trust Discovery", "tactic": "Discovery", "confidence": "HIGH",
     "description": "Domain/trust enumeration tool detected."},
    {"pattern": r"(type.*8|type_string.*Echo Request|echo.request)", "technique": "T1018",
     "name": "Remote System Discovery", "tactic": "Discovery", "confidence": "LOW",
     "log_types": ["stream_icmp"],
     "description": "ICMP ping sweep / host discovery detected."},

    # ── Lateral Movement ────────────────────────────────────────
    {"pattern": r"(psexec|paexec|RemCom|winexesvc)", "technique": "T1021.002",
     "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement", "confidence": "HIGH",
     "description": "PsExec-style remote execution detected."},
    {"pattern": r"(port.*(3389)|rdp|mstsc|termsrv)", "technique": "T1021.001",
     "name": "Remote Desktop Protocol", "tactic": "Lateral Movement", "confidence": "MEDIUM",
     "description": "RDP activity detected."},
    {"pattern": r"(wmi|wmic|wmiprvse)", "technique": "T1047",
     "name": "Windows Management Instrumentation", "tactic": "Execution", "confidence": "MEDIUM",
     "description": "WMI execution detected."},

    # ── Command and Control ─────────────────────────────────────
    {"pattern": r"(cobalt\s*strike|beacon|cobaltstrike)", "technique": "T1071.001",
     "name": "Web Protocols (C2)", "tactic": "Command and Control", "confidence": "CRITICAL",
     "description": "Cobalt Strike C2 indicators detected."},
    {"pattern": r"(dns.*(tunnel|exfil)|iodine|dnscat)", "technique": "T1071.004",
     "name": "DNS C2", "tactic": "Command and Control", "confidence": "HIGH",
     "description": "DNS tunneling / C2 indicators detected."},
    {"pattern": r"(\.onion|tor2web|torproject)", "technique": "T1090.003",
     "name": "Multi-hop Proxy (Tor)", "tactic": "Command and Control", "confidence": "HIGH",
     "description": "Tor network usage detected."},

    # ── Initial Access / Web Attacks (IIS/HTTP) ─────────────────
    {"pattern": r"(SELECT.*FROM|UNION.*SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE)", "technique": "T1190",
     "name": "Exploit Public-Facing Application (SQLi)", "tactic": "Initial Access", "confidence": "CRITICAL",
     "log_types": ["iis", "stream_http"],
     "description": "SQL injection attempt detected in web logs."},
    {"pattern": r"(<script|javascript:|onerror=|onload=|<img.*onerror)", "technique": "T1189",
     "name": "Drive-by Compromise (XSS)", "tactic": "Initial Access", "confidence": "HIGH",
     "log_types": ["iis", "stream_http"],
     "description": "Cross-site scripting (XSS) attempt detected."},
    {"pattern": r"(\.\.\/|\.\.\\|etc/passwd|boot\.ini|win\.ini)", "technique": "T1083",
     "name": "File and Directory Discovery (Path Traversal)", "tactic": "Discovery", "confidence": "HIGH",
     "log_types": ["iis", "stream_http"],
     "description": "Path traversal / directory traversal attempt detected."},
    {"pattern": r"(\/cmd\.exe|\/bin\/sh|\/bin\/bash|cmd\+/c\+)", "technique": "T1059",
     "name": "Command and Scripting Interpreter (RCE)", "tactic": "Execution", "confidence": "CRITICAL",
     "log_types": ["iis", "stream_http"],
     "description": "Remote code execution attempt via web shell/command injection."},
    {"pattern": r"(sc_status.*50[0-9]|HTTP/1\.\d\"\s+50[0-9])", "technique": "T1190",
     "name": "Server Error (Possible Exploit)", "tactic": "Initial Access", "confidence": "LOW",
     "log_types": ["iis", "stream_http"],
     "description": "HTTP 5xx server errors may indicate exploitation attempts."},
    {"pattern": r"(wp-login|wp-admin|xmlrpc\.php|/administrator/)", "technique": "T1190",
     "name": "CMS Attack Surface", "tactic": "Initial Access", "confidence": "MEDIUM",
     "log_types": ["iis", "stream_http"],
     "description": "CMS admin page access / brute force attempt detected."},

    # ── Firewall specific ───────────────────────────────────────
    {"pattern": r"action=(blocked|deny|drop|reject)", "technique": "T1190",
     "name": "Blocked Connection (Possible Scan)", "tactic": "Initial Access", "confidence": "LOW",
     "log_types": ["fortigate_utm", "fortigate_event"],
     "description": "Firewall blocked connection — possible scan or exploitation."},
    {"pattern": r"subtype=webfilter.*action=blocked", "technique": "T1204.001",
     "name": "Malicious Link (Web Filter Block)", "tactic": "Execution", "confidence": "MEDIUM",
     "log_types": ["fortigate_utm"],
     "description": "Web filter blocked a potentially malicious URL."},
    {"pattern": r"apprisk=(critical|high)", "technique": "T1071.001",
     "name": "High-Risk Application", "tactic": "Command and Control", "confidence": "MEDIUM",
     "log_types": ["fortigate_utm"],
     "description": "High-risk application detected by application control."},
    {"pattern": r"subtype=ips.*action=dropped", "technique": "T1190",
     "name": "IPS Detection", "tactic": "Initial Access", "confidence": "HIGH",
     "log_types": ["fortigate_utm", "fortigate_event"],
     "description": "Intrusion Prevention System detected and blocked an attack."},

    # ── Windows Event Log specific ──────────────────────────────
    {"pattern": r"EventCode=(4624|4625|4648)", "technique": "T1078",
     "name": "Valid Accounts (Logon Events)", "tactic": "Initial Access", "confidence": "LOW",
     "log_types": ["wineventlog_sec", "wineventlog_sys", "wineventlog_app"],
     "description": "Windows logon event — track for brute force or pass-the-hash."},
    {"pattern": r"EventCode=(4688|1)", "technique": "T1059",
     "name": "Process Creation", "tactic": "Execution", "confidence": "LOW",
     "log_types": ["wineventlog_sec", "sysmon"],
     "description": "New process creation event — review command line for suspicious activity."},
    {"pattern": r"EventCode=(7045|4697)", "technique": "T1543.003",
     "name": "Service Installation", "tactic": "Persistence", "confidence": "HIGH",
     "log_types": ["wineventlog_sys", "wineventlog_sec"],
     "description": "New Windows service installed — check for malicious services."},
    {"pattern": r"EventCode=(4720|4722|4726|4738)", "technique": "T1136",
     "name": "Create Account", "tactic": "Persistence", "confidence": "HIGH",
     "log_types": ["wineventlog_sec"],
     "description": "User account creation/modification/deletion detected."},
    {"pattern": r"EventCode=(1102|517)", "technique": "T1070.001",
     "name": "Clear Windows Event Logs", "tactic": "Defense Evasion", "confidence": "CRITICAL",
     "log_types": ["wineventlog_sec", "wineventlog_sys"],
     "description": "Audit log was cleared — possible evidence destruction."},
    {"pattern": r"SourceName=.*Service Control Manager", "technique": "T1543.003",
     "name": "Service State Change", "tactic": "Persistence", "confidence": "LOW",
     "log_types": ["wineventlog_sys"],
     "description": "Service state change via SCM detected."},

    # ── Nessus / Vulnerability ──────────────────────────────────
    {"pattern": r"severity.*[34]", "technique": "T1190",
     "name": "High/Critical Vulnerability", "tactic": "Initial Access", "confidence": "HIGH",
     "log_types": ["nessus_scan"],
     "description": "Nessus detected a high or critical severity vulnerability."},

    # ── Impact ──────────────────────────────────────────────────
    {"pattern": r"(vssadmin|wmic\s+shadowcopy|bcdedit.*recoveryenabled)", "technique": "T1490",
     "name": "Inhibit System Recovery", "tactic": "Impact", "confidence": "CRITICAL",
     "description": "Shadow copy deletion or recovery inhibition detected."},
    {"pattern": r"(\.encrypted|\.locked|ransom|crypt0)", "technique": "T1486",
     "name": "Data Encrypted for Impact", "tactic": "Impact", "confidence": "HIGH",
     "description": "Ransomware / encryption indicators detected."},

    # ── DHCP ────────────────────────────────────────────────────
    {"pattern": r"opcode.*DHCPDISCOVER|opcode.*DHCPREQUEST", "technique": "T1557",
     "name": "DHCP Activity (Network Mapping)", "tactic": "Credential Access", "confidence": "LOW",
     "log_types": ["stream_dhcp"],
     "description": "DHCP request activity — useful for host inventory and rogue device detection."},

    # ── Email ───────────────────────────────────────────────────
    {"pattern": r"(\.exe|\.scr|\.bat|\.cmd|\.ps1|\.vbs|\.js)\b", "technique": "T1566.001",
     "name": "Spearphishing Attachment", "tactic": "Initial Access", "confidence": "MEDIUM",
     "log_types": ["stream_mapi"],
     "description": "Executable attachment extension found in email traffic."},
]


def map_logs_to_mitre(df: pd.DataFrame, log_type: str = "") -> List[Dict]:
    """Scan log data against MITRE ATT&CK detection rules."""
    if "_raw" in df.columns:
        search_series = df["_raw"].astype(str)
    else:
        search_series = df.apply(lambda row: " ".join(row.astype(str)), axis=1)

    all_text_lower = "\n".join(search_series.head(50000).tolist()).lower()

    matches = []
    for rule in MITRE_LOG_RULES:
        try:
            found = re.findall(rule["pattern"], all_text_lower, re.IGNORECASE)
            if found:
                count = len(found)
                samples = []
                for text in search_series.head(50000):
                    if re.search(rule["pattern"], str(text), re.IGNORECASE):
                        samples.append(str(text)[:200])
                        if len(samples) >= 3:
                            break
                matches.append({
                    "technique_id": rule["technique"],
                    "technique_name": rule["name"],
                    "tactic": rule["tactic"],
                    "confidence": rule["confidence"],
                    "description": rule["description"],
                    "match_count": count,
                    "sample_evidence": samples,
                })
        except re.error:
            continue

    confidence_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    matches.sort(key=lambda x: (confidence_order.get(x["confidence"], 99), -x["match_count"]))
    return matches


# ════════════════════════════════════════════════════════════════════
# STATISTICAL ANALYSIS
# ════════════════════════════════════════════════════════════════════
def compute_top_talkers(df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    results = {}

    # Source IPs
    for col in ["srcip", "src_ip", "source_ip", "c_ip", "src"]:
        if col in df.columns:
            results["top_source_ips"] = df[col].value_counts().head(20).reset_index()
            results["top_source_ips"].columns = ["IP", "Count"]
            break

    # Dest IPs
    for col in ["dstip", "dest_ip", "destination_ip", "s_ip", "dst"]:
        if col in df.columns:
            results["top_dest_ips"] = df[col].value_counts().head(20).reset_index()
            results["top_dest_ips"].columns = ["IP", "Count"]
            break

    # Dest Ports
    for col in ["dstport", "dest_port", "s_port", "DestinationPort"]:
        if col in df.columns:
            results["top_dest_ports"] = df[col].value_counts().head(20).reset_index()
            results["top_dest_ports"].columns = ["Port", "Count"]
            break

    # Hostnames / URLs
    for col in ["hostname", "cs_uri_stem", "url", "site", "dest_host"]:
        if col in df.columns:
            results["top_hostnames"] = df[col].value_counts().head(20).reset_index()
            results["top_hostnames"].columns = ["Hostname", "Count"]
            break

    # Action / Status codes
    for col in ["action", "sc_status", "status", "Action", "eventtype"]:
        if col in df.columns:
            results["action_distribution"] = df[col].value_counts().reset_index()
            results["action_distribution"].columns = ["Action", "Count"]
            break

    # Processes
    for col in ["process_image", "Image", "ProcessName", "CommandLine"]:
        if col in df.columns:
            results["top_processes"] = df[col].value_counts().head(20).reset_index()
            results["top_processes"].columns = ["Process", "Count"]
            break

    # Registry operations
    for col in ["registry_type", "EventType"]:
        if col in df.columns:
            results["registry_operations"] = df[col].value_counts().reset_index()
            results["registry_operations"].columns = ["Operation", "Count"]
            break

    # HTTP methods
    for col in ["http_method", "cs_method", "method"]:
        if col in df.columns:
            results["http_methods"] = df[col].value_counts().reset_index()
            results["http_methods"].columns = ["Method", "Count"]
            break

    # User agents
    for col in ["http_user_agent", "cs_user_agent", "user_agent"]:
        if col in df.columns:
            results["top_user_agents"] = df[col].value_counts().head(15).reset_index()
            results["top_user_agents"].columns = ["User-Agent", "Count"]
            break

    # Event sources (WinEventLog)
    for col in ["SourceName", "EventCode", "LogName"]:
        if col in df.columns:
            results[f"top_{col}"] = df[col].value_counts().head(20).reset_index()
            results[f"top_{col}"].columns = [col, "Count"]
            break

    # Nessus severity
    if "severity" in df.columns:
        results["severity_distribution"] = df["severity"].value_counts().reset_index()
        results["severity_distribution"].columns = ["Severity", "Count"]

    # Nessus plugin families
    if "plugin_family" in df.columns:
        results["plugin_families"] = df["plugin_family"].value_counts().head(15).reset_index()
        results["plugin_families"].columns = ["Plugin Family", "Count"]

    # DHCP opcodes
    if "opcode" in df.columns:
        results["dhcp_opcodes"] = df["opcode"].value_counts().reset_index()
        results["dhcp_opcodes"].columns = ["DHCP Opcode", "Count"]

    # FortiGate categories
    for col in ["catdesc", "app", "subtype"]:
        if col in df.columns:
            results[f"top_{col}"] = df[col].value_counts().head(15).reset_index()
            results[f"top_{col}"].columns = [col.replace("catdesc", "Category").replace("app", "Application").replace("subtype", "Subtype"), "Count"]

    return results


def compute_time_series(df: pd.DataFrame) -> Optional[pd.DataFrame]:
    time_col = None
    for col in ["_time", "timestamp", "time", "datetime", "date", "endtime"]:
        if col in df.columns:
            time_col = col
            break
    if time_col is None:
        return None
    try:
        df["_parsed_time"] = pd.to_datetime(
            df[time_col].astype(str).str.replace(r"\s+\w{3,4}$", "", regex=True),
            errors="coerce"
        )
        df_valid = df.dropna(subset=["_parsed_time"])
        if len(df_valid) < 2:
            return None
        total_span = (df_valid["_parsed_time"].max() - df_valid["_parsed_time"].min()).total_seconds()
        if total_span > 86400 * 7:
            freq = "1h"
        elif total_span > 86400:
            freq = "10min"
        elif total_span > 3600:
            freq = "1min"
        else:
            freq = "10s"
        ts = df_valid.set_index("_parsed_time").resample(freq).size().reset_index()
        ts.columns = ["time", "event_count"]
        return ts
    except Exception:
        return None
