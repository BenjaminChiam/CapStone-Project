"""
Sigma Rule Generator Module
Auto-generates Sigma detection rules from enriched IOC data
using the Jinja2 templating engine.
"""

import re
from datetime import datetime, timezone
from typing import Optional


class SigmaGenerator:
    """
    Generates valid Sigma .yml detection rules from IOC data.
    Uses string templating (Jinja2-compatible patterns).

    Sigma is the open standard for SIEM-agnostic detection rules.
    Generated rules can be converted to Splunk SPL, Elastic KQL,
    Microsoft Sentinel KQL, etc. via sigma-cli or pySigma.
    """

    # ── Sigma Templates ─────────────────────────────────────────────
    IP_TEMPLATE = """title: Malicious IP - {ioc}
id: {rule_id}
status: experimental
description: >
    Auto-generated Sigma rule for suspicious IP address {ioc}.
    Consensus Score: {score}/100 | Threat Level: {threat_level}
    {description}
references:
    - https://www.virustotal.com/gui/ip-address/{ioc}
author: Threat Hunt Assistant (Auto-Generated)
date: {date}
tags:
    - attack.command_and_control
    {mitre_tags}
logsource:
    category: firewall
    product: any
detection:
    selection_dst:
        DestinationIp: '{ioc}'
    selection_src:
        SourceIp: '{ioc}'
    condition: selection_dst or selection_src
fields:
    - SourceIp
    - DestinationIp
    - DestinationPort
    - Action
falsepositives:
    - Legitimate services hosted on this IP
    - CDN or cloud provider shared infrastructure
level: {level}"""

    DOMAIN_TEMPLATE = """title: Malicious Domain - {ioc}
id: {rule_id}
status: experimental
description: >
    Auto-generated Sigma rule for suspicious domain {ioc}.
    Consensus Score: {score}/100 | Threat Level: {threat_level}
    {description}
references:
    - https://www.virustotal.com/gui/domain/{ioc}
author: Threat Hunt Assistant (Auto-Generated)
date: {date}
tags:
    - attack.command_and_control
    {mitre_tags}
logsource:
    category: dns
    product: any
detection:
    selection:
        query|contains: '{ioc}'
    condition: selection
fields:
    - query
    - answer
    - src_ip
falsepositives:
    - Legitimate subdomain usage
    - Parked domains
level: {level}"""

    HASH_TEMPLATE = """title: Malicious File Hash - {ioc}
id: {rule_id}
status: experimental
description: >
    Auto-generated Sigma rule for suspicious file hash.
    Hash: {ioc}
    Consensus Score: {score}/100 | Threat Level: {threat_level}
    {description}
references:
    - https://www.virustotal.com/gui/file/{ioc}
author: Threat Hunt Assistant (Auto-Generated)
date: {date}
tags:
    - attack.execution
    {mitre_tags}
logsource:
    category: process_creation
    product: windows
detection:
    selection_md5:
        Hashes|contains: 'MD5={ioc}'
    selection_sha1:
        Hashes|contains: 'SHA1={ioc}'
    selection_sha256:
        Hashes|contains: 'SHA256={ioc}'
    condition: selection_md5 or selection_sha1 or selection_sha256
fields:
    - Image
    - Hashes
    - ParentImage
    - CommandLine
    - User
falsepositives:
    - Legitimate software with matching hash (unlikely)
level: {level}"""

    # ── IOC Type Detection ──────────────────────────────────────────
    @staticmethod
    def _detect_type(ioc: str) -> str:
        ioc = ioc.strip()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
            return "ip"
        if re.match(r"^[a-fA-F0-9]{32}$", ioc):
            return "hash"
        if re.match(r"^[a-fA-F0-9]{40}$", ioc):
            return "hash"
        if re.match(r"^[a-fA-F0-9]{64}$", ioc):
            return "hash"
        return "domain"

    @staticmethod
    def _generate_rule_id(ioc: str) -> str:
        """Generate a deterministic UUID-like ID from the IOC."""
        import hashlib
        h = hashlib.md5(ioc.encode()).hexdigest()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

    @staticmethod
    def _score_to_level(score: float) -> str:
        if score >= 75:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        return "low"

    # ── Main Generator ──────────────────────────────────────────────
    def generate(
        self,
        ioc: str,
        score: float = 0,
        threat_level: str = "UNKNOWN",
        description: str = "",
        mitre_ids: Optional[list] = None,
    ) -> str:
        """
        Generate a Sigma rule YAML string for the given IOC.

        Args:
            ioc: The indicator (IP, domain, or hash)
            score: Consensus risk score (0-100)
            threat_level: CRITICAL / HIGH / MEDIUM / LOW
            description: Additional context
            mitre_ids: List of MITRE Technique IDs (e.g., ["T1071.001"])

        Returns:
            Valid Sigma rule as YAML string
        """
        ioc = ioc.strip()
        ioc_type = self._detect_type(ioc)
        rule_id = self._generate_rule_id(ioc)
        date = datetime.now(timezone.utc).strftime("%Y/%m/%d")
        level = self._score_to_level(score)

        # Format MITRE tags
        mitre_tags = ""
        if mitre_ids:
            mitre_tags = "\n    ".join(
                [f"- attack.{tid.lower().replace('.', '_')}" for tid in mitre_ids]
            )

        template_map = {
            "ip": self.IP_TEMPLATE,
            "domain": self.DOMAIN_TEMPLATE,
            "hash": self.HASH_TEMPLATE,
        }

        template = template_map.get(ioc_type, self.DOMAIN_TEMPLATE)

        return template.format(
            ioc=ioc,
            rule_id=rule_id,
            date=date,
            score=score,
            threat_level=threat_level,
            description=description or "No additional context provided.",
            mitre_tags=mitre_tags,
            level=level,
        )
