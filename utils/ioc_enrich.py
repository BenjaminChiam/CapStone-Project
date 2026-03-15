"""
IOC Enrichment Module — Enhanced Multi-Source Intelligence
==========================================================
Sources:
1. VirusTotal       — File/IP/Domain/URL reputation
2. Shodan           — Open ports, banners, vulns, ASN
3. AbuseIPDB        — IP abuse reports and confidence scoring
4. GreyNoise        — Internet noise vs targeted attack classification
5. URLhaus          — Malicious URL database (abuse.ch)
6. MalwareBazaar    — Malware sample lookup by hash (abuse.ch)
7. WHOIS            — Domain registration and ownership data
"""

import hashlib
import json
import re
import socket
import requests
import streamlit as st
from datetime import datetime
from typing import Optional


class IOCEnricher:
    """
    Enriches IOCs (IPs, domains, hashes, URLs) from 7 intelligence sources.
    Uses Streamlit cache as a lightweight caching layer.
    """

    def __init__(
        self,
        vt_api_key: str = "",
        shodan_api_key: str = "",
        abuseipdb_api_key: str = "",
        greynoise_api_key: str = "",
        whoisxml_api_key: str = "",
    ):
        self.vt_api_key = vt_api_key
        self.shodan_api_key = shodan_api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self.greynoise_api_key = greynoise_api_key
        self.whoisxml_api_key = whoisxml_api_key

    # ── IOC Type Detection ──────────────────────────────────────────
    @staticmethod
    def detect_ioc_type(ioc: str) -> str:
        ioc = ioc.strip()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
            return "ip"
        if re.match(r"^https?://", ioc):
            return "url"
        if re.match(r"^[a-fA-F0-9]{32}$", ioc):
            return "hash_md5"
        if re.match(r"^[a-fA-F0-9]{40}$", ioc):
            return "hash_sha1"
        if re.match(r"^[a-fA-F0-9]{64}$", ioc):
            return "hash_sha256"
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$", ioc):
            return "domain"
        return "unknown"

    # ── 1. VirusTotal ───────────────────────────────────────────────
    def _query_virustotal(self, ioc: str, ioc_type: str) -> dict:
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
                return {"source": "virustotal", "error": "Rate limited (429)"}
            else:
                return {"source": "virustotal", "error": f"HTTP {resp.status_code}"}
        except requests.RequestException as e:
            return {"source": "virustotal", "error": str(e)}

    # ── 2. Shodan ───────────────────────────────────────────────────
    def _query_shodan(self, ioc: str, ioc_type: str) -> dict:
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

    # ── 3. AbuseIPDB ────────────────────────────────────────────────
    def _query_abuseipdb(self, ioc: str, ioc_type: str) -> dict:
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

    # ── 4. GreyNoise ────────────────────────────────────────────────
    def _query_greynoise(self, ioc: str, ioc_type: str) -> dict:
        """
        GreyNoise classifies IPs as:
        - 'benign': known good scanners (e.g., Shodan, Censys)
        - 'malicious': known bad actors
        - 'unknown': not seen in GreyNoise dataset
        This helps filter out internet noise from targeted attacks.
        """
        if ioc_type != "ip":
            return {"source": "greynoise", "note": "GreyNoise only supports IP lookups"}

        try:
            # Community API (free, no key needed for basic lookups)
            headers = {}
            if self.greynoise_api_key:
                headers["key"] = self.greynoise_api_key
                url = f"https://api.greynoise.io/v3/community/{ioc}"
            else:
                url = f"https://api.greynoise.io/v3/community/{ioc}"

            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "source": "greynoise",
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "classification": data.get("classification", "unknown"),
                    "name": data.get("name", "N/A"),
                    "message": data.get("message", ""),
                    "last_seen": data.get("last_seen", "N/A"),
                }
            else:
                return {"source": "greynoise", "error": f"HTTP {resp.status_code}"}
        except requests.RequestException as e:
            return {"source": "greynoise", "error": str(e)}

    # ── 5. URLhaus (abuse.ch) ───────────────────────────────────────
    def _query_urlhaus(self, ioc: str, ioc_type: str) -> dict:
        """
        URLhaus is a free database of malicious URLs used for malware distribution.
        No API key required.
        """
        if ioc_type not in ("url", "domain"):
            return {"source": "urlhaus", "note": "URLhaus supports URL and domain lookups"}

        try:
            if ioc_type == "url":
                url = "https://urlhaus-api.abuse.ch/v1/url/"
                payload = {"url": ioc}
            else:
                url = "https://urlhaus-api.abuse.ch/v1/host/"
                payload = {"host": ioc}

            resp = requests.post(url, data=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "no_results":
                    return {"source": "urlhaus", "status": "not_found", "message": "Not in URLhaus database (good sign)"}
                return {
                    "source": "urlhaus",
                    "status": "found",
                    "threat": data.get("threat", "N/A"),
                    "url_status": data.get("url_status", "N/A"),
                    "date_added": data.get("date_added", "N/A"),
                    "tags": data.get("tags", []),
                    "urls_count": data.get("urls_count", 0) if ioc_type == "domain" else None,
                    "blacklists": data.get("blacklists", {}),
                    "reporter": data.get("reporter", "N/A"),
                }
            else:
                return {"source": "urlhaus", "error": f"HTTP {resp.status_code}"}
        except requests.RequestException as e:
            return {"source": "urlhaus", "error": str(e)}

    # ── 6. MalwareBazaar (abuse.ch) ─────────────────────────────────
    def _query_malwarebazaar(self, ioc: str, ioc_type: str) -> dict:
        """
        MalwareBazaar is a free malware sample repository.
        Supports hash lookups (MD5, SHA1, SHA256). No API key required.
        """
        if ioc_type not in ("hash_md5", "hash_sha1", "hash_sha256"):
            return {"source": "malwarebazaar", "note": "MalwareBazaar supports hash lookups only"}

        hash_type_map = {"hash_md5": "md5_hash", "hash_sha1": "sha1_hash", "hash_sha256": "sha256_hash"}

        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            payload = {"query": "get_info", "hash": ioc}
            resp = requests.post(url, data=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "hash_not_found":
                    return {"source": "malwarebazaar", "status": "not_found", "message": "Hash not in MalwareBazaar"}
                sample = data.get("data", [{}])[0] if data.get("data") else {}
                return {
                    "source": "malwarebazaar",
                    "status": "found",
                    "file_name": sample.get("file_name", "N/A"),
                    "file_type": sample.get("file_type", "N/A"),
                    "file_size": sample.get("file_size", 0),
                    "signature": sample.get("signature", "N/A"),
                    "tags": sample.get("tags", []),
                    "delivery_method": sample.get("delivery_method", "N/A"),
                    "intelligence": {
                        "clamav": sample.get("intelligence", {}).get("clamav", []),
                        "downloads": sample.get("intelligence", {}).get("downloads", 0),
                        "uploads": sample.get("intelligence", {}).get("uploads", "N/A"),
                    },
                    "first_seen": sample.get("first_seen", "N/A"),
                    "last_seen": sample.get("last_seen", "N/A"),
                    "country": sample.get("origin_country", "N/A"),
                }
            else:
                return {"source": "malwarebazaar", "error": f"HTTP {resp.status_code}"}
        except requests.RequestException as e:
            return {"source": "malwarebazaar", "error": str(e)}

    # ── 7. WHOIS Lookup ─────────────────────────────────────────────
    def _query_whois(self, ioc: str, ioc_type: str) -> dict:
        """
        WHOIS lookup via WhoisXML API (if key provided) or raw socket fallback.
        Useful for checking domain age, registrar, and registration dates.
        Newly registered domains are a strong phishing indicator.
        """
        if ioc_type not in ("domain", "ip"):
            return {"source": "whois", "note": "WHOIS supports domain and IP lookups"}

        # Prefer WhoisXML API if key is available
        if self.whoisxml_api_key:
            try:
                url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
                params = {
                    "apiKey": self.whoisxml_api_key,
                    "domainName": ioc,
                    "outputFormat": "JSON",
                }
                resp = requests.get(url, params=params, timeout=15)
                if resp.status_code == 200:
                    data = resp.json().get("WhoisRecord", {})
                    return {
                        "source": "whoisxml_api",
                        "domain_name": data.get("domainName", "N/A"),
                        "registrar": data.get("registrarName", "N/A"),
                        "creation_date": data.get("createdDateNormalized", "N/A"),
                        "expiration_date": data.get("expiresDateNormalized", "N/A"),
                        "updated_date": data.get("updatedDateNormalized", "N/A"),
                        "registrant_country": data.get("registrant", {}).get("country", "N/A"),
                        "registrant_org": data.get("registrant", {}).get("organization", "N/A"),
                        "name_servers": [ns.get("host", "") for ns in data.get("nameServers", {}).get("hostNames", []) if isinstance(ns, dict)] if isinstance(data.get("nameServers", {}).get("hostNames"), list) else data.get("nameServers", {}).get("hostNames", []),
                        "domain_age_days": data.get("estimatedDomainAge", "N/A"),
                        "contact_email": data.get("contactEmail", "N/A"),
                    }
                else:
                    return {"source": "whoisxml_api", "error": f"HTTP {resp.status_code}"}
            except requests.RequestException as e:
                return {"source": "whoisxml_api", "error": str(e)}

        # Fallback: raw socket WHOIS
        try:
            whois_server = "whois.iana.org" if ioc_type == "domain" else "whois.arin.net"
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((whois_server, 43))
            s.send((ioc + "\r\n").encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            raw_text = response.decode("utf-8", errors="ignore")
            parsed = {"source": "whois_socket", "raw_length": len(raw_text)}
            for line in raw_text.split("\n"):
                ll = line.lower().strip()
                if "registrar:" in ll:
                    parsed["registrar"] = line.split(":", 1)[-1].strip()
                elif "creation date:" in ll or "created:" in ll:
                    parsed["creation_date"] = line.split(":", 1)[-1].strip()
                elif "expiration date:" in ll or "expiry date:" in ll:
                    parsed["expiration_date"] = line.split(":", 1)[-1].strip()
                elif "registrant country:" in ll or "country:" in ll:
                    if "country" not in parsed:
                        parsed["country"] = line.split(":", 1)[-1].strip()
            return parsed
        except Exception as e:
            return {"source": "whois", "error": str(e)}

    # ── Consensus Scoring ───────────────────────────────────────────
    @staticmethod
    def calculate_consensus_score(results: dict) -> dict:
        """
        Enhanced Weighted Consensus Scoring algorithm.
        Aggregates verdicts from all sources for a unified confidence score.
        """
        score = 0
        factors = []

        # VirusTotal weight (30%)
        vt = results.get("virustotal", {})
        if "malicious" in vt:
            total = max(vt.get("total_engines", 1), 1)
            mal_ratio = vt["malicious"] / total
            vt_score = mal_ratio * 30
            score += vt_score
            factors.append(f"VirusTotal: {vt['malicious']}/{total} engines ({vt_score:.1f}/30)")

        # AbuseIPDB weight (25%)
        abuse = results.get("abuseipdb", {})
        if "abuse_confidence_score" in abuse:
            abuse_score = (abuse["abuse_confidence_score"] / 100) * 25
            score += abuse_score
            factors.append(f"AbuseIPDB: {abuse['abuse_confidence_score']}% ({abuse_score:.1f}/25)")

        # Shodan weight (15%)
        shodan = results.get("shodan", {})
        if "ports" in shodan:
            suspicious_ports = {22, 23, 445, 3389, 4444, 5555, 8080, 8443, 9090}
            found = set(shodan["ports"]) & suspicious_ports
            port_score = min(len(found) * 3, 8)
            vuln_score = min(len(shodan.get("vulns", [])) * 2, 7)
            shodan_total = port_score + vuln_score
            score += shodan_total
            factors.append(f"Shodan: {len(shodan['ports'])} ports, {len(shodan.get('vulns', []))} vulns ({shodan_total:.1f}/15)")

        # GreyNoise weight (10%)
        gn = results.get("greynoise", {})
        if "classification" in gn:
            if gn["classification"] == "malicious":
                score += 10
                factors.append("GreyNoise: Classified MALICIOUS (10/10)")
            elif gn["classification"] == "benign":
                score -= 5
                factors.append("GreyNoise: Classified BENIGN (-5)")
            elif gn.get("noise"):
                score += 3
                factors.append("GreyNoise: Internet noise/scanner (3/10)")

        # URLhaus weight (10%)
        urlhaus = results.get("urlhaus", {})
        if urlhaus.get("status") == "found":
            score += 10
            factors.append("URLhaus: Found in malicious URL database (10/10)")

        # MalwareBazaar weight (10%)
        mb = results.get("malwarebazaar", {})
        if mb.get("status") == "found":
            score += 10
            factors.append(f"MalwareBazaar: Known malware — {mb.get('signature', 'N/A')} (10/10)")

        score = max(0, min(score, 100))

        if score >= 75:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 25:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "consensus_score": round(score, 1),
            "threat_level": level,
            "scoring_factors": factors,
            "sources_queried": len([k for k in results if isinstance(results.get(k), dict) and "error" not in results.get(k, {})]),
        }

    # ── Main Enrichment Orchestrator ────────────────────────────────
    def enrich(self, ioc: str, disabled_sources: set = None) -> dict:
        """
        Main enrichment function. Queries all relevant sources
        and returns a consolidated report with consensus scoring.
        disabled_sources: set of source names to skip (e.g., {"virustotal", "shodan"})
        """
        ioc = ioc.strip()
        ioc_type = self.detect_ioc_type(ioc)
        disabled = disabled_sources or set()

        result = {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "disabled_sources": list(disabled),
        }

        if ioc_type == "unknown":
            result["error"] = "Could not determine IOC type"
            return result

        # Query enabled sources only
        if "virustotal" not in disabled:
            result["virustotal"] = self._query_virustotal(ioc, ioc_type)
        else:
            result["virustotal"] = {"source": "virustotal", "status": "disabled"}

        if "shodan" not in disabled:
            result["shodan"] = self._query_shodan(ioc, ioc_type)
        else:
            result["shodan"] = {"source": "shodan", "status": "disabled"}

        if "abuseipdb" not in disabled:
            result["abuseipdb"] = self._query_abuseipdb(ioc, ioc_type)
        else:
            result["abuseipdb"] = {"source": "abuseipdb", "status": "disabled"}

        if "greynoise" not in disabled:
            result["greynoise"] = self._query_greynoise(ioc, ioc_type)
        else:
            result["greynoise"] = {"source": "greynoise", "status": "disabled"}

        if "urlhaus" not in disabled:
            result["urlhaus"] = self._query_urlhaus(ioc, ioc_type)
        else:
            result["urlhaus"] = {"source": "urlhaus", "status": "disabled"}

        if "malwarebazaar" not in disabled:
            result["malwarebazaar"] = self._query_malwarebazaar(ioc, ioc_type)
        else:
            result["malwarebazaar"] = {"source": "malwarebazaar", "status": "disabled"}

        if "whois" not in disabled:
            result["whois"] = self._query_whois(ioc, ioc_type)
        else:
            result["whois"] = {"source": "whois", "status": "disabled"}

        # Calculate consensus
        result["consensus"] = self.calculate_consensus_score(result)

        return result
