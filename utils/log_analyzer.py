"""
Log Analysis Utilities
======================
Parsers for common log formats (FortiGate UTM, Splunk streams, Windows Registry,
Sysmon, generic CSV). Includes IOC extraction, MITRE ATT&CK auto-mapping,
and statistical anomaly analysis.
"""

import re
import json
import csv
import gzip
import io
import math
from collections import Counter
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import pandas as pd
import numpy as np


# ════════════════════════════════════════════════════════════════════
# LOG TYPE DETECTION
# ════════════════════════════════════════════════════════════════════
def detect_log_type(df: pd.DataFrame) -> str:
    """Auto-detect log type from DataFrame columns or sourcetype field."""
    cols = set(df.columns)

    # Check sourcetype column first (Splunk exports)
    if "sourcetype" in cols:
        st = df["sourcetype"].iloc[0] if len(df) > 0 else ""
        if "fgt_utm" in str(st):
            return "fortigate_utm"
        if "icmp" in str(st):
            return "stream_icmp"
        if "mapi" in str(st):
            return "stream_mapi"
        if "dns" in str(st):
            return "stream_dns"
        if "http" in str(st):
            return "stream_http"

    if "source" in cols:
        src = df["source"].iloc[0] if len(df) > 0 else ""
        if "WinRegistry" in str(src):
            return "winregistry"
        if "Sysmon" in str(src) or "sysmon" in str(src):
            return "sysmon"
        if "WinEventLog" in str(src):
            return "wineventlog"

    # Check for common column patterns
    if {"src_ip", "dest_ip", "src_port", "dest_port"}.issubset(cols):
        return "network_flow"
    if {"srcip", "dstip", "action"}.issubset(cols):
        return "firewall"

    return "generic"


# ════════════════════════════════════════════════════════════════════
# LOG PARSERS
# ════════════════════════════════════════════════════════════════════
def load_log_file(uploaded_file) -> pd.DataFrame:
    """Load a log file (CSV, CSV.GZ, or plain text) into a DataFrame."""
    filename = uploaded_file.name.lower()
    content = uploaded_file.read()

    try:
        if filename.endswith(".gz"):
            decompressed = gzip.decompress(content)
            df = pd.read_csv(io.BytesIO(decompressed), low_memory=False, on_bad_lines="skip")
        elif filename.endswith(".csv"):
            df = pd.read_csv(io.BytesIO(content), low_memory=False, on_bad_lines="skip")
        elif filename.endswith(".json") or filename.endswith(".jsonl"):
            lines = content.decode("utf-8", errors="ignore").strip().split("\n")
            records = [json.loads(line) for line in lines if line.strip()]
            df = pd.DataFrame(records)
        else:
            # Try CSV first, then treat as raw text
            try:
                df = pd.read_csv(io.BytesIO(content), low_memory=False, on_bad_lines="skip")
            except Exception:
                lines = content.decode("utf-8", errors="ignore").strip().split("\n")
                df = pd.DataFrame({"_raw": lines, "_time": range(len(lines))})
        return df
    except Exception as e:
        return pd.DataFrame({"error": [str(e)]})


def parse_raw_field(df: pd.DataFrame, log_type: str) -> pd.DataFrame:
    """Parse the _raw field based on detected log type into structured columns."""
    if "_raw" not in df.columns:
        return df

    if log_type == "fortigate_utm":
        return _parse_fortigate(df)
    elif log_type in ("stream_icmp", "stream_mapi", "stream_dns", "stream_http"):
        return _parse_json_stream(df)
    elif log_type == "winregistry":
        return _parse_winregistry(df)
    else:
        return df


def _parse_fortigate(df: pd.DataFrame) -> pd.DataFrame:
    """Parse FortiGate key=value logs."""
    parsed_rows = []
    for _, row in df.head(50000).iterrows():  # Limit for performance
        raw = str(row.get("_raw", ""))
        record = {"_time": row.get("_time", ""), "host": row.get("host", "")}
        # Extract key=value pairs, handling quoted values
        pairs = re.findall(r'(\w+)=(?:"([^"]*)"|([\S]*))', raw)
        for key, quoted_val, plain_val in pairs:
            record[key] = quoted_val if quoted_val else plain_val
        parsed_rows.append(record)
    return pd.DataFrame(parsed_rows)


def _parse_json_stream(df: pd.DataFrame) -> pd.DataFrame:
    """Parse JSON-formatted stream logs."""
    parsed_rows = []
    for _, row in df.head(50000).iterrows():
        raw = str(row.get("_raw", ""))
        record = {"_time": row.get("_time", ""), "host": row.get("host", "")}
        try:
            # Clean escaped quotes from Splunk CSV export
            cleaned = raw.replace('""', '"')
            if cleaned.startswith('"') and cleaned.endswith('"'):
                cleaned = cleaned[1:-1]
            parsed = json.loads(cleaned)
            record.update(parsed)
        except (json.JSONDecodeError, Exception):
            record["_raw"] = raw
        parsed_rows.append(record)
    return pd.DataFrame(parsed_rows)


def _parse_winregistry(df: pd.DataFrame) -> pd.DataFrame:
    """Parse Windows Registry multi-line key=value logs."""
    parsed_rows = []
    for _, row in df.head(50000).iterrows():
        raw = str(row.get("_raw", ""))
        record = {"_time": row.get("_time", ""), "host": row.get("host", "")}
        pairs = re.findall(r'(\w+)="([^"]*)"', raw)
        for key, val in pairs:
            record[key] = val
        # Also capture non-quoted key=value
        pairs2 = re.findall(r'^(\w+)=(\S+)$', raw, re.MULTILINE)
        for key, val in pairs2:
            if key not in record:
                record[key] = val
        parsed_rows.append(record)
    return pd.DataFrame(parsed_rows)


# ════════════════════════════════════════════════════════════════════
# IOC EXTRACTION
# ════════════════════════════════════════════════════════════════════
# RFC1918 private IP ranges to filter
_PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
]


def is_private_ip(ip: str) -> bool:
    return any(r.match(ip) for r in _PRIVATE_RANGES)


def extract_iocs_from_df(df: pd.DataFrame) -> Dict[str, List[str]]:
    """Extract unique IOCs (IPs, domains, hashes, URLs) from a DataFrame."""
    all_text = " ".join(df.astype(str).values.flatten())

    # IPs
    ips = set(re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", all_text))
    public_ips = {ip for ip in ips if not is_private_ip(ip)}
    private_ips = {ip for ip in ips if is_private_ip(ip)}

    # Domains
    domains = set(re.findall(
        r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b",
        all_text
    ))
    # Filter out common non-domains
    domains = {d for d in domains if not re.match(r"^\d+\.\d+\.\d+\.\d+$", d)
               and len(d) > 4 and "." in d}

    # Hashes
    md5s = set(re.findall(r"\b([a-fA-F0-9]{32})\b", all_text))
    sha1s = set(re.findall(r"\b([a-fA-F0-9]{40})\b", all_text))
    sha256s = set(re.findall(r"\b([a-fA-F0-9]{64})\b", all_text))

    # URLs
    urls = set(re.findall(r"(https?://[^\s\"',;]+)", all_text))

    return {
        "public_ips": sorted(public_ips)[:100],
        "private_ips": sorted(private_ips)[:50],
        "domains": sorted(domains)[:100],
        "md5_hashes": sorted(md5s)[:50],
        "sha1_hashes": sorted(sha1s)[:50],
        "sha256_hashes": sorted(sha256s)[:50],
        "urls": sorted(urls)[:50],
    }


# ════════════════════════════════════════════════════════════════════
# MITRE ATT&CK AUTO-MAPPING FROM LOGS
# ════════════════════════════════════════════════════════════════════
# Rules-based detection patterns
MITRE_LOG_RULES = [
    # Registry persistence
    {"pattern": r"(Run|RunOnce|CurrentVersion\\Run)", "field": "_raw",
     "technique": "T1547.001", "name": "Registry Run Keys / Startup Folder",
     "tactic": "Persistence", "confidence": "HIGH",
     "description": "Registry modification to autostart keys detected."},
    {"pattern": r"(Services\\|CurrentControlSet\\Services)", "field": "_raw",
     "technique": "T1543.003", "name": "Windows Service",
     "tactic": "Persistence", "confidence": "MEDIUM",
     "description": "Windows service registry modification detected."},

    # Process execution
    {"pattern": r"(powershell|pwsh)", "field": "_raw",
     "technique": "T1059.001", "name": "PowerShell",
     "tactic": "Execution", "confidence": "MEDIUM",
     "description": "PowerShell execution detected in logs."},
    {"pattern": r"(cmd\.exe|command\.com)", "field": "_raw",
     "technique": "T1059.003", "name": "Windows Command Shell",
     "tactic": "Execution", "confidence": "LOW",
     "description": "Command shell execution detected."},
    {"pattern": r"(wscript|cscript|\.vbs|\.vbe)", "field": "_raw",
     "technique": "T1059.005", "name": "Visual Basic",
     "tactic": "Execution", "confidence": "MEDIUM",
     "description": "VBScript execution detected."},
    {"pattern": r"(python|\.py\b)", "field": "_raw",
     "technique": "T1059.006", "name": "Python",
     "tactic": "Execution", "confidence": "LOW",
     "description": "Python execution detected."},
    {"pattern": r"(rundll32)", "field": "_raw",
     "technique": "T1218.011", "name": "Rundll32",
     "tactic": "Defense Evasion", "confidence": "MEDIUM",
     "description": "Rundll32 proxy execution detected."},

    # Credential access
    {"pattern": r"(lsass|mimikatz|sekurlsa|wce\.exe)", "field": "_raw",
     "technique": "T1003.001", "name": "LSASS Memory",
     "tactic": "Credential Access", "confidence": "HIGH",
     "description": "LSASS credential dumping activity detected."},
    {"pattern": r"(ntds\.dit|ntdsutil)", "field": "_raw",
     "technique": "T1003.003", "name": "NTDS",
     "tactic": "Credential Access", "confidence": "HIGH",
     "description": "Active Directory database access detected."},

    # Discovery
    {"pattern": r"(net\s+(user|group|localgroup|share|view))", "field": "_raw",
     "technique": "T1087", "name": "Account Discovery",
     "tactic": "Discovery", "confidence": "MEDIUM",
     "description": "Account/network enumeration command detected."},
    {"pattern": r"(whoami|systeminfo|ipconfig|hostname)", "field": "_raw",
     "technique": "T1082", "name": "System Information Discovery",
     "tactic": "Discovery", "confidence": "LOW",
     "description": "System information gathering detected."},

    # Lateral movement
    {"pattern": r"(psexec|paexec|RemCom)", "field": "_raw",
     "technique": "T1021.002", "name": "SMB/Windows Admin Shares",
     "tactic": "Lateral Movement", "confidence": "HIGH",
     "description": "PsExec-style remote execution detected."},
    {"pattern": r"(port\s*3389|rdp|mstsc)", "field": "_raw",
     "technique": "T1021.001", "name": "Remote Desktop Protocol",
     "tactic": "Lateral Movement", "confidence": "MEDIUM",
     "description": "RDP activity detected."},

    # Network / C2
    {"pattern": r"(cobalt\s*strike|beacon|cobaltstrike)", "field": "_raw",
     "technique": "T1071.001", "name": "Web Protocols",
     "tactic": "Command and Control", "confidence": "CRITICAL",
     "description": "Cobalt Strike C2 beacon indicators detected."},
    {"pattern": r"(dns\s*tunnel|iodine|dnscat)", "field": "_raw",
     "technique": "T1071.004", "name": "DNS",
     "tactic": "Command and Control", "confidence": "HIGH",
     "description": "DNS tunneling indicators detected."},
    {"pattern": r"(tor\b|\.onion|tor2web)", "field": "_raw",
     "technique": "T1090.003", "name": "Multi-hop Proxy",
     "tactic": "Command and Control", "confidence": "HIGH",
     "description": "Tor/onion routing detected."},

    # Firewall specific
    {"pattern": r"action=(blocked|deny|drop|reject)", "field": "_raw",
     "technique": "T1190", "name": "Exploit Public-Facing Application",
     "tactic": "Initial Access", "confidence": "LOW",
     "description": "Blocked connection attempt — possible exploitation attempt."},
    {"pattern": r"subtype=webfilter.*action=blocked", "field": "_raw",
     "technique": "T1204.001", "name": "Malicious Link",
     "tactic": "Execution", "confidence": "MEDIUM",
     "description": "Web filter blocked a potentially malicious URL."},

    # Exfiltration / Impact
    {"pattern": r"(rar|7z|zip).*password", "field": "_raw",
     "technique": "T1560.001", "name": "Archive via Utility",
     "tactic": "Collection", "confidence": "MEDIUM",
     "description": "Password-protected archive creation detected."},
    {"pattern": r"(vssadmin|wmic\s+shadowcopy|bcdedit)", "field": "_raw",
     "technique": "T1490", "name": "Inhibit System Recovery",
     "tactic": "Impact", "confidence": "HIGH",
     "description": "Shadow copy deletion or recovery inhibition detected."},
    {"pattern": r"(\.encrypted|ransom|crypt|locked)", "field": "_raw",
     "technique": "T1486", "name": "Data Encrypted for Impact",
     "tactic": "Impact", "confidence": "HIGH",
     "description": "Ransomware / encryption indicators detected."},

    # ICMP specific
    {"pattern": r"type.*8|type_string.*Echo Request", "field": "_raw",
     "technique": "T1018", "name": "Remote System Discovery",
     "tactic": "Discovery", "confidence": "LOW",
     "description": "ICMP echo requests (ping sweep) detected."},
]


def map_logs_to_mitre(df: pd.DataFrame) -> List[Dict]:
    """
    Scan log data against rule-based MITRE ATT&CK detection patterns.
    Returns a list of matched techniques with evidence.
    """
    # Concatenate searchable text from all relevant columns
    if "_raw" in df.columns:
        search_series = df["_raw"].astype(str)
    else:
        search_series = df.apply(lambda row: " ".join(row.astype(str)), axis=1)

    # Combine all text for fast regex searching
    all_text = "\n".join(search_series.head(50000).tolist())
    all_text_lower = all_text.lower()

    matches = []
    for rule in MITRE_LOG_RULES:
        pattern = rule["pattern"]
        try:
            found = re.findall(pattern, all_text_lower, re.IGNORECASE)
            if found:
                # Count occurrences
                count = len(found)
                # Find sample matching rows
                sample_matches = []
                for idx, text in enumerate(search_series.head(50000)):
                    if re.search(pattern, str(text), re.IGNORECASE):
                        sample_matches.append(str(text)[:200])
                        if len(sample_matches) >= 3:
                            break

                matches.append({
                    "technique_id": rule["technique"],
                    "technique_name": rule["name"],
                    "tactic": rule["tactic"],
                    "confidence": rule["confidence"],
                    "description": rule["description"],
                    "match_count": count,
                    "sample_evidence": sample_matches,
                })
        except re.error:
            continue

    # Sort by confidence then count
    confidence_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    matches.sort(key=lambda x: (confidence_order.get(x["confidence"], 99), -x["match_count"]))

    return matches


# ════════════════════════════════════════════════════════════════════
# STATISTICAL ANALYSIS
# ════════════════════════════════════════════════════════════════════
def compute_top_talkers(df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    """Identify top source/destination IPs, ports, and hostnames."""
    results = {}

    # Try various column names for source IPs
    for col in ["srcip", "src_ip", "source_ip", "SourceIP", "src"]:
        if col in df.columns:
            results["top_source_ips"] = (
                df[col].value_counts().head(20).reset_index()
            )
            results["top_source_ips"].columns = ["IP", "Count"]
            break

    for col in ["dstip", "dest_ip", "destination_ip", "DestinationIP", "dst"]:
        if col in df.columns:
            results["top_dest_ips"] = (
                df[col].value_counts().head(20).reset_index()
            )
            results["top_dest_ips"].columns = ["IP", "Count"]
            break

    for col in ["dstport", "dest_port", "DestinationPort"]:
        if col in df.columns:
            results["top_dest_ports"] = (
                df[col].value_counts().head(20).reset_index()
            )
            results["top_dest_ports"].columns = ["Port", "Count"]
            break

    for col in ["hostname", "host", "dest_host"]:
        if col in df.columns:
            results["top_hostnames"] = (
                df[col].value_counts().head(20).reset_index()
            )
            results["top_hostnames"].columns = ["Hostname", "Count"]
            break

    for col in ["action", "Action", "status"]:
        if col in df.columns:
            results["action_distribution"] = (
                df[col].value_counts().reset_index()
            )
            results["action_distribution"].columns = ["Action", "Count"]
            break

    for col in ["process_image", "Image", "ProcessName"]:
        if col in df.columns:
            results["top_processes"] = (
                df[col].value_counts().head(20).reset_index()
            )
            results["top_processes"].columns = ["Process", "Count"]
            break

    for col in ["registry_type", "EventType"]:
        if col in df.columns:
            results["registry_operations"] = (
                df[col].value_counts().reset_index()
            )
            results["registry_operations"].columns = ["Operation", "Count"]
            break

    return results


def compute_time_series(df: pd.DataFrame) -> Optional[pd.DataFrame]:
    """Compute event frequency over time for timeline visualization."""
    time_col = None
    for col in ["_time", "timestamp", "time", "datetime", "date", "endtime"]:
        if col in df.columns:
            time_col = col
            break

    if time_col is None:
        return None

    try:
        df["_parsed_time"] = pd.to_datetime(df[time_col], errors="coerce", utc=True)
        df_valid = df.dropna(subset=["_parsed_time"])
        if len(df_valid) == 0:
            # Try without UTC
            df["_parsed_time"] = pd.to_datetime(df[time_col].str.replace(r"\s+\w+$", "", regex=True),
                                                  errors="coerce")
            df_valid = df.dropna(subset=["_parsed_time"])

        if len(df_valid) == 0:
            return None

        # Resample to appropriate interval
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
