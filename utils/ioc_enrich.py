"""
IOC Enrichment Module
Handles enrichment of Indicators of Compromise via external APIs.
Implements local caching to reduce API calls and handle rate limits.
"""

import hashlib
import json
import re
import time
import requests
import streamlit as st
from datetime import datetime, timedelta
from typing import Optional


class IOCEnricher:
    """
    Enriches IOCs (IPs, domains, hashes, URLs) using:
    - VirusTotal API
    - Shodan API
    - AbuseIPDB API

    Uses st.cache_data as a lightweight cache layer.
    For production, swap with Redis (see README).
    """

    def __init__(self, vt_api_key: str = "", shodan_api_key: str = "", abuseipdb_api_key: str = ""):
        self.vt_api_key = vt_api_key
        self.shodan_api_key = shodan_api_key
        self.abuseipdb_api_key = abuseipdb_api_key

    # ── IOC Type Detection ──────────────────────────────────────────
    @staticmethod
    def detect_ioc_type(ioc: str) -> str:
        """Classify the IOC as ip, domain, hash_md5, hash_sha1, hash_sha256, or url."""
        ioc = ioc.strip()

        # IPv4
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
            return "ip"

        # URL
        if re.match(r"^https?://", ioc):
            return "url"

        # MD5
        if re.match(r"^[a-fA-F0-9]{32}$", ioc):
            return "hash_md5"

        # SHA1
        if re.match(r"^[a-fA-F0-9]{40}$", ioc):
            return "hash_sha1"

        # SHA256
        if re.match(r"^[a-fA-F0-9]{64}$", ioc):
            return "hash_sha256"

        # Default to domain
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$", ioc):
            return "domain"

        return "unknown"

    # ── Cache Key Generation ────────────────────────────────────────
    @staticmethod
    def _cache_key(ioc: str) -> str:
        """Generate SHA-256 cache key for an IOC."""
        return hashlib.sha256(ioc.strip().lower().encode()).hexdigest()

    # ── VirusTotal Enrichment ───────────────────────────────────────
    def _query_virustotal(self, ioc: str, ioc_type: str) -> dict:
        """Query VirusTotal API v3."""
        if not self.vt_api_key:
            return {"source": "virustotal", "error": "API key not configured"}

        headers = {"x-apikey": self.vt_api_key}
        base_url = "https://www.virustotal.com/api/v3"

        endpoint_map = {
            "ip": f"{base_url}/ip_addresses/{ioc}",
            "domain": f"{base_url}/domains/{ioc}",
            "hash_md5": f"{base_url}/files/{ioc}",
            "hash_sha1": f"{base_url}/files/{ioc}",
            "hash_sha256": f"{base_url}/files/{ioc}",
            "url": f"{base_url}/urls/{hashlib.sha256(ioc.encode()).hexdigest()}",
        }

        endpoint = endpoint_map.get(ioc_type)
        if not endpoint:
            return {"source": "virustotal", "error": f"Unsupported IOC type: {ioc_type}"}

        try:
            resp = requests.get(endpoint, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "source": "virustotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "reputation": data.get("reputation", "N/A"),
                    "tags": data.get("tags", []),
                    "last_analysis_date": data.get("last_analysis_date", "N/A"),
                }
            elif resp.status_code == 429:
                return {"source": "virustotal", "error": "Rate limited (429). Try again later."}
            else:
                return {"source": "virustotal", "error": f"HTTP {resp.status_code}"}
        except requests.RequestException as e:
            return {"source": "virustotal", "error": str(e)}

    # ── Shodan Enrichment ───────────────────────────────────────────
    def _query_shodan(self, ioc: str, ioc_type: str) -> dict:
        """Query Shodan API for IP enrichment."""
        if not self.shodan_api_key:
            return {"source": "shodan", "error": "API key not configured"}

        if ioc_type != "ip":
            return {"source": "shodan", "note": "Shodan only supports IP lookups"}

        try:
            url = f"https://api.shodan.io/shodan/host/{ioc}?key={self.shodan_api_key}"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "source": "shodan",
                    "ports": data.get("ports", []),
                    "org": data.get("org", "N/A"),
                    "asn": data.get("asn", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "country": data.get("country_name", "N/A"),
                    "city": data.get("city", "N/A"),
                    "os": data.get("os", "N/A"),
                    "hostnames": data.get("hostnames", []),
                    "vulns": data.get("vulns", []),
                    "last_update": data.get("last_update", "N/A"),
                }
            else:
                return {"source": "shodan", "error": f"HTTP {resp.status_code}"}
        except requests.RequestException as e:
            return {"source": "shodan", "error": str(e)}

    # ── AbuseIPDB Enrichment ────────────────────────────────────────
    def _query_abuseipdb(self, ioc: str, ioc_type: str) -> dict:
        """Query AbuseIPDB API."""
        if not self.abuseipdb_api_key:
            return {"source": "abuseipdb", "error": "API key not configured"}

        if ioc_type != "ip":
            return {"source": "abuseipdb", "note": "AbuseIPDB only supports IP lookups"}

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.abuseipdb_api_key, "Accept": "application/json"}
            params = {"ipAddress": ioc, "maxAgeInDays": 90, "verbose": True}
            resp = requests.get(url, headers=headers, params=params, timeout=15)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "source": "abuseipdb",
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "domain": data.get("domain", "N/A"),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "usage_type": data.get("usageType", "N/A"),
                    "last_reported": data.get("lastReportedAt", "N/A"),
                }
            else:
                return {"source": "abuseipdb", "error": f"HTTP {resp.status_code}"}
        except requests.RequestException as e:
            return {"source": "abuseipdb", "error": str(e)}

    # ── Consensus Scoring ───────────────────────────────────────────
    @staticmethod
    def calculate_consensus_score(results: dict) -> dict:
        """
        Weighted Consensus Scoring algorithm.
        Aggregates verdicts from multiple sources to produce a confidence score.
        """
        score = 0
        factors = []
        max_score = 100

        # VirusTotal weight (40%)
        vt = results.get("virustotal", {})
        if "malicious" in vt:
            total = vt.get("total_engines", 1)
            mal_ratio = vt["malicious"] / max(total, 1)
            vt_score = mal_ratio * 40
            score += vt_score
            factors.append(f"VirusTotal: {vt['malicious']}/{total} engines detected ({vt_score:.1f}/40)")

        # AbuseIPDB weight (35%)
        abuse = results.get("abuseipdb", {})
        if "abuse_confidence_score" in abuse:
            abuse_score = (abuse["abuse_confidence_score"] / 100) * 35
            score += abuse_score
            factors.append(f"AbuseIPDB: {abuse['abuse_confidence_score']}% confidence ({abuse_score:.1f}/35)")

        # Shodan weight (25%) — based on open ports & vulns
        shodan = results.get("shodan", {})
        if "ports" in shodan:
            suspicious_ports = {22, 23, 445, 3389, 4444, 5555, 8080, 8443, 9090}
            found_suspicious = set(shodan["ports"]) & suspicious_ports
            port_score = min(len(found_suspicious) * 5, 15)
            vuln_score = min(len(shodan.get("vulns", [])) * 2, 10)
            shodan_score = port_score + vuln_score
            score += shodan_score
            factors.append(f"Shodan: {len(shodan['ports'])} ports, {len(shodan.get('vulns', []))} vulns ({shodan_score:.1f}/25)")

        # Determine threat level
        if score >= 75:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 25:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "consensus_score": round(min(score, max_score), 1),
            "threat_level": level,
            "scoring_factors": factors,
        }

    # ── Main Enrichment Orchestrator ────────────────────────────────
    def enrich(self, ioc: str) -> dict:
        """
        Main enrichment function. Detects IOC type and queries all relevant sources.
        Returns a consolidated enrichment report with consensus scoring.
        """
        ioc = ioc.strip()
        ioc_type = self.detect_ioc_type(ioc)

        result = {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "virustotal": {},
            "shodan": {},
            "abuseipdb": {},
            "consensus": {},
        }

        if ioc_type == "unknown":
            result["error"] = "Could not determine IOC type"
            return result

        # Query sources
        result["virustotal"] = self._query_virustotal(ioc, ioc_type)
        result["shodan"] = self._query_shodan(ioc, ioc_type)
        result["abuseipdb"] = self._query_abuseipdb(ioc, ioc_type)

        # Calculate consensus
        result["consensus"] = self.calculate_consensus_score(result)

        return result
