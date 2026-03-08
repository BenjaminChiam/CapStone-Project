"""
MITRE ATT&CK Enterprise Matrix — Comprehensive Data Module
============================================================
Modeled after the mitre-attack/attack-data-model schema structure.
Contains: Tactics, Techniques (with sub-techniques), Groups (APTs),
Software/Tools, Mitigations, and Relationships.

Data source: MITRE ATT&CK Enterprise Matrix v16+
Reference: https://attack.mitre.org/
"""

from typing import List, Dict, Optional
from dataclasses import dataclass, field


# ════════════════════════════════════════════════════════════════════
# DATA CLASSES (mirrors STIX SDO/SRO schema)
# ════════════════════════════════════════════════════════════════════
@dataclass
class Tactic:
    id: str                  # e.g., "TA0001"
    name: str                # e.g., "Initial Access"
    shortname: str           # e.g., "initial-access"
    description: str
    order: int               # Kill chain order (1-14)


@dataclass
class Technique:
    id: str                  # e.g., "T1566"
    name: str                # e.g., "Phishing"
    tactic_ids: List[str]    # e.g., ["TA0001"]
    description: str
    platforms: List[str] = field(default_factory=list)
    is_subtechnique: bool = False
    parent_id: Optional[str] = None
    detection: str = ""
    data_sources: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    permissions_required: List[str] = field(default_factory=list)


@dataclass
class Group:
    id: str                  # e.g., "G0016"
    name: str                # e.g., "APT29"
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    technique_ids: List[str] = field(default_factory=list)
    software_ids: List[str] = field(default_factory=list)
    country: str = ""


@dataclass
class Software:
    id: str                  # e.g., "S0154"
    name: str                # e.g., "Cobalt Strike"
    sw_type: str             # "malware" or "tool"
    description: str = ""
    technique_ids: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)


@dataclass
class Mitigation:
    id: str                  # e.g., "M1049"
    name: str
    description: str = ""
    technique_ids: List[str] = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════
# TACTICS — The 14 ATT&CK Enterprise Tactics (Kill Chain)
# ════════════════════════════════════════════════════════════════════
TACTICS: List[Tactic] = [
    Tactic("TA0043", "Reconnaissance", "reconnaissance",
           "Gathering information to plan future operations.", 1),
    Tactic("TA0042", "Resource Development", "resource-development",
           "Establishing resources to support operations.", 2),
    Tactic("TA0001", "Initial Access", "initial-access",
           "Trying to get into your network.", 3),
    Tactic("TA0002", "Execution", "execution",
           "Trying to run malicious code.", 4),
    Tactic("TA0003", "Persistence", "persistence",
           "Trying to maintain their foothold.", 5),
    Tactic("TA0004", "Privilege Escalation", "privilege-escalation",
           "Trying to gain higher-level permissions.", 6),
    Tactic("TA0005", "Defense Evasion", "defense-evasion",
           "Trying to avoid being detected.", 7),
    Tactic("TA0006", "Credential Access", "credential-access",
           "Stealing account names and passwords.", 8),
    Tactic("TA0007", "Discovery", "discovery",
           "Trying to figure out your environment.", 9),
    Tactic("TA0008", "Lateral Movement", "lateral-movement",
           "Trying to move through your environment.", 10),
    Tactic("TA0009", "Collection", "collection",
           "Gathering data of interest to their goal.", 11),
    Tactic("TA0011", "Command and Control", "command-and-control",
           "Communicating with compromised systems.", 12),
    Tactic("TA0010", "Exfiltration", "exfiltration",
           "Stealing data from your network.", 13),
    Tactic("TA0040", "Impact", "impact",
           "Manipulate, interrupt, or destroy systems and data.", 14),
]

# ════════════════════════════════════════════════════════════════════
# TECHNIQUES — Enterprise Techniques with Tactic Mappings
# ════════════════════════════════════════════════════════════════════
TECHNIQUES: List[Technique] = [
    # ── Reconnaissance ──────────────────────────────────────────
    Technique("T1595", "Active Scanning", ["TA0043"], "Scanning infrastructure to identify targets.",
             platforms=["PRE"], data_sources=["Network Traffic"]),
    Technique("T1595.001", "Scanning IP Blocks", ["TA0043"], "Scanning IP ranges for open services.",
             is_subtechnique=True, parent_id="T1595"),
    Technique("T1595.002", "Vulnerability Scanning", ["TA0043"], "Scanning for known vulnerabilities.",
             is_subtechnique=True, parent_id="T1595"),
    Technique("T1592", "Gather Victim Host Information", ["TA0043"], "Gathering info about victim hosts.",
             platforms=["PRE"]),
    Technique("T1589", "Gather Victim Identity Information", ["TA0043"], "Collecting victim identity data.",
             platforms=["PRE"]),
    Technique("T1590", "Gather Victim Network Information", ["TA0043"], "Mapping victim network topology.",
             platforms=["PRE"]),
    Technique("T1598", "Phishing for Information", ["TA0043"], "Sending phishing to elicit information.",
             platforms=["PRE"]),
    Technique("T1593", "Search Open Websites/Domains", ["TA0043"], "Searching open web for victim info.",
             platforms=["PRE"]),

    # ── Resource Development ────────────────────────────────────
    Technique("T1583", "Acquire Infrastructure", ["TA0042"], "Buying or leasing infrastructure for operations.",
             platforms=["PRE"]),
    Technique("T1583.001", "Domains", ["TA0042"], "Acquiring domains for operations.",
             is_subtechnique=True, parent_id="T1583"),
    Technique("T1586", "Compromise Accounts", ["TA0042"], "Hijacking existing accounts.",
             platforms=["PRE"]),
    Technique("T1587", "Develop Capabilities", ["TA0042"], "Building malware, exploits, or tools.",
             platforms=["PRE"]),
    Technique("T1588", "Obtain Capabilities", ["TA0042"], "Buying or downloading tools and malware.",
             platforms=["PRE"]),
    Technique("T1585", "Establish Accounts", ["TA0042"], "Creating accounts for operations.",
             platforms=["PRE"]),
    Technique("T1608", "Stage Capabilities", ["TA0042"], "Uploading tools to infrastructure.",
             platforms=["PRE"]),

    # ── Initial Access ──────────────────────────────────────────
    Technique("T1566", "Phishing", ["TA0001"], "Sending phishing messages to gain access.",
             platforms=["Windows", "macOS", "Linux"],
             data_sources=["Email", "Network Traffic", "Application Log"],
             mitigations=["M1049", "M1031", "M1054", "M1017"]),
    Technique("T1566.001", "Spearphishing Attachment", ["TA0001"], "Sending malicious attachments via email.",
             is_subtechnique=True, parent_id="T1566", platforms=["Windows", "macOS", "Linux"]),
    Technique("T1566.002", "Spearphishing Link", ["TA0001"], "Sending emails with malicious links.",
             is_subtechnique=True, parent_id="T1566", platforms=["Windows", "macOS", "Linux"]),
    Technique("T1566.003", "Spearphishing via Service", ["TA0001"], "Phishing via third-party services.",
             is_subtechnique=True, parent_id="T1566"),
    Technique("T1190", "Exploit Public-Facing Application", ["TA0001"],
             "Exploiting vulnerabilities in internet-facing applications.",
             platforms=["Windows", "Linux", "macOS", "Containers"],
             data_sources=["Application Log", "Network Traffic"],
             mitigations=["M1048", "M1030", "M1050", "M1051"]),
    Technique("T1133", "External Remote Services", ["TA0001", "TA0003"],
             "Leveraging VPNs, Citrix, or other external services.",
             platforms=["Windows", "Linux", "macOS"],
             mitigations=["M1035", "M1032", "M1030"]),
    Technique("T1200", "Hardware Additions", ["TA0001"], "Introducing rogue hardware devices.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1078", "Valid Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"],
             "Using legitimate credentials for access.",
             platforms=["Windows", "Linux", "macOS", "Azure AD", "Google Workspace"],
             mitigations=["M1027", "M1026", "M1032"]),
    Technique("T1189", "Drive-by Compromise", ["TA0001"], "Compromising users via visiting websites.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1195", "Supply Chain Compromise", ["TA0001"], "Manipulating supply chain products.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1199", "Trusted Relationship", ["TA0001"], "Abusing trusted third-party relationships.",
             platforms=["Windows", "Linux", "macOS"]),

    # ── Execution ───────────────────────────────────────────────
    Technique("T1059", "Command and Scripting Interpreter", ["TA0002"],
             "Abusing command-line and scripting interpreters.",
             platforms=["Windows", "macOS", "Linux"],
             data_sources=["Command", "Process", "Script"],
             mitigations=["M1049", "M1038", "M1026", "M1042"]),
    Technique("T1059.001", "PowerShell", ["TA0002"], "Using PowerShell commands and scripts.",
             is_subtechnique=True, parent_id="T1059", platforms=["Windows"]),
    Technique("T1059.002", "AppleScript", ["TA0002"], "Using AppleScript for execution.",
             is_subtechnique=True, parent_id="T1059", platforms=["macOS"]),
    Technique("T1059.003", "Windows Command Shell", ["TA0002"], "Using cmd.exe for execution.",
             is_subtechnique=True, parent_id="T1059", platforms=["Windows"]),
    Technique("T1059.004", "Unix Shell", ["TA0002"], "Using bash/sh for execution.",
             is_subtechnique=True, parent_id="T1059", platforms=["Linux", "macOS"]),
    Technique("T1059.005", "Visual Basic", ["TA0002"], "Using VBScript or VBA macros.",
             is_subtechnique=True, parent_id="T1059", platforms=["Windows"]),
    Technique("T1059.006", "Python", ["TA0002"], "Using Python scripts for execution.",
             is_subtechnique=True, parent_id="T1059", platforms=["Windows", "Linux", "macOS"]),
    Technique("T1059.007", "JavaScript", ["TA0002"], "Using JavaScript/JScript for execution.",
             is_subtechnique=True, parent_id="T1059", platforms=["Windows", "macOS", "Linux"]),
    Technique("T1203", "Exploitation for Client Execution", ["TA0002"],
             "Exploiting software vulnerabilities for code execution.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1204", "User Execution", ["TA0002"], "Relying on user interaction to execute.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1204.001", "Malicious Link", ["TA0002"], "User clicks a malicious link.",
             is_subtechnique=True, parent_id="T1204"),
    Technique("T1204.002", "Malicious File", ["TA0002"], "User opens a malicious file.",
             is_subtechnique=True, parent_id="T1204"),
    Technique("T1047", "Windows Management Instrumentation", ["TA0002"],
             "Using WMI for execution.", platforms=["Windows"]),
    Technique("T1053", "Scheduled Task/Job", ["TA0002", "TA0003", "TA0004"],
             "Abusing task scheduling for execution and persistence.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1053.005", "Scheduled Task", ["TA0002", "TA0003", "TA0004"],
             "Using Windows Task Scheduler.", is_subtechnique=True, parent_id="T1053"),
    Technique("T1106", "Native API", ["TA0002"], "Using OS native APIs for execution.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1569", "System Services", ["TA0002"], "Abusing system services to execute.",
             platforms=["Windows", "macOS"]),

    # ── Persistence ─────────────────────────────────────────────
    Technique("T1547", "Boot or Logon Autostart Execution", ["TA0003", "TA0004"],
             "Configuring system to run programs at boot/logon.",
             platforms=["Windows", "macOS", "Linux"]),
    Technique("T1547.001", "Registry Run Keys / Startup Folder", ["TA0003", "TA0004"],
             "Adding programs to registry run keys or startup folder.",
             is_subtechnique=True, parent_id="T1547", platforms=["Windows"]),
    Technique("T1136", "Create Account", ["TA0003"], "Creating new accounts for persistence.",
             platforms=["Windows", "Linux", "macOS", "Azure AD"]),
    Technique("T1543", "Create or Modify System Process", ["TA0003", "TA0004"],
             "Creating or modifying system-level processes.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1543.003", "Windows Service", ["TA0003", "TA0004"],
             "Creating or modifying Windows services.",
             is_subtechnique=True, parent_id="T1543", platforms=["Windows"]),
    Technique("T1053", "Scheduled Task/Job", ["TA0003"], "Using scheduled tasks for persistence.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1505", "Server Software Component", ["TA0003"],
             "Abusing server software for persistence.", platforms=["Windows", "Linux"]),
    Technique("T1505.003", "Web Shell", ["TA0003"], "Installing web shells on servers.",
             is_subtechnique=True, parent_id="T1505", platforms=["Windows", "Linux"]),
    Technique("T1098", "Account Manipulation", ["TA0003", "TA0004"],
             "Manipulating accounts to maintain access.", platforms=["Windows", "Linux", "Azure AD"]),
    Technique("T1176", "Browser Extensions", ["TA0003"], "Installing malicious browser extensions.",
             platforms=["Windows", "macOS", "Linux"]),
    Technique("T1574", "Hijack Execution Flow", ["TA0003", "TA0004"],
             "Hijacking how the OS runs programs.", platforms=["Windows", "Linux", "macOS"]),

    # ── Privilege Escalation ────────────────────────────────────
    Technique("T1548", "Abuse Elevation Control Mechanism", ["TA0004", "TA0005"],
             "Bypassing UAC or sudo for elevated access.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1548.002", "Bypass User Account Control", ["TA0004", "TA0005"],
             "Bypassing Windows UAC.", is_subtechnique=True, parent_id="T1548", platforms=["Windows"]),
    Technique("T1068", "Exploitation for Privilege Escalation", ["TA0004"],
             "Exploiting software vulnerabilities for privileges.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1134", "Access Token Manipulation", ["TA0004", "TA0005"],
             "Manipulating access tokens to operate under different security contexts.",
             platforms=["Windows"]),
    Technique("T1611", "Escape to Host", ["TA0004"], "Breaking out of containers to the host.",
             platforms=["Windows", "Linux", "Containers"]),

    # ── Defense Evasion ─────────────────────────────────────────
    Technique("T1027", "Obfuscated Files or Information", ["TA0005"],
             "Encrypting or encoding files to evade detection.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1027.001", "Binary Padding", ["TA0005"], "Adding junk data to change file hash.",
             is_subtechnique=True, parent_id="T1027"),
    Technique("T1140", "Deobfuscate/Decode Files or Information", ["TA0005"],
             "Using built-in utilities to decode obfuscated content.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1036", "Masquerading", ["TA0005"], "Manipulating names/locations to evade detection.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1036.005", "Match Legitimate Name or Location", ["TA0005"],
             "Naming malicious files like legitimate ones.",
             is_subtechnique=True, parent_id="T1036"),
    Technique("T1055", "Process Injection", ["TA0004", "TA0005"],
             "Injecting code into running processes.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1055.001", "Dynamic-link Library Injection", ["TA0004", "TA0005"],
             "Injecting DLLs into process memory.", is_subtechnique=True, parent_id="T1055"),
    Technique("T1070", "Indicator Removal", ["TA0005"], "Deleting or modifying evidence.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1070.001", "Clear Windows Event Logs", ["TA0005"], "Clearing event log entries.",
             is_subtechnique=True, parent_id="T1070", platforms=["Windows"]),
    Technique("T1070.004", "File Deletion", ["TA0005"], "Deleting files to remove evidence.",
             is_subtechnique=True, parent_id="T1070"),
    Technique("T1562", "Impair Defenses", ["TA0005"], "Disabling or modifying security tools.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1562.001", "Disable or Modify Tools", ["TA0005"], "Killing or tampering with security software.",
             is_subtechnique=True, parent_id="T1562"),
    Technique("T1218", "System Binary Proxy Execution", ["TA0005"],
             "Using signed binaries to proxy execution of malicious content.",
             platforms=["Windows"]),
    Technique("T1218.011", "Rundll32", ["TA0005"], "Using rundll32.exe to execute malicious DLLs.",
             is_subtechnique=True, parent_id="T1218", platforms=["Windows"]),
    Technique("T1497", "Virtualization/Sandbox Evasion", ["TA0005", "TA0007"],
             "Detecting and evading virtualized environments.", platforms=["Windows", "Linux", "macOS"]),
    Technique("T1553", "Subvert Trust Controls", ["TA0005"], "Undermining security trust mechanisms.",
             platforms=["Windows", "Linux", "macOS"]),

    # ── Credential Access ───────────────────────────────────────
    Technique("T1110", "Brute Force", ["TA0006"], "Trying many passwords to gain access.",
             platforms=["Windows", "Linux", "macOS", "Azure AD"],
             mitigations=["M1032", "M1027", "M1036"]),
    Technique("T1110.001", "Password Guessing", ["TA0006"], "Guessing common passwords.",
             is_subtechnique=True, parent_id="T1110"),
    Technique("T1110.003", "Password Spraying", ["TA0006"], "Trying one password against many accounts.",
             is_subtechnique=True, parent_id="T1110"),
    Technique("T1003", "OS Credential Dumping", ["TA0006"], "Dumping credentials from the OS.",
             platforms=["Windows", "Linux"],
             mitigations=["M1043", "M1027", "M1026"]),
    Technique("T1003.001", "LSASS Memory", ["TA0006"], "Dumping credentials from LSASS process memory.",
             is_subtechnique=True, parent_id="T1003", platforms=["Windows"]),
    Technique("T1003.003", "NTDS", ["TA0006"], "Dumping Active Directory database.",
             is_subtechnique=True, parent_id="T1003", platforms=["Windows"]),
    Technique("T1003.006", "DCSync", ["TA0006"], "Simulating a domain controller to replicate credentials.",
             is_subtechnique=True, parent_id="T1003", platforms=["Windows"]),
    Technique("T1558", "Steal or Forge Kerberos Tickets", ["TA0006"],
             "Stealing or forging Kerberos tickets.", platforms=["Windows"]),
    Technique("T1558.003", "Kerberoasting", ["TA0006"], "Requesting service tickets to crack offline.",
             is_subtechnique=True, parent_id="T1558", platforms=["Windows"]),
    Technique("T1555", "Credentials from Password Stores", ["TA0006"],
             "Searching for credentials in password stores.", platforms=["Windows", "Linux", "macOS"]),
    Technique("T1557", "Adversary-in-the-Middle", ["TA0006", "TA0009"],
             "Positioning between two endpoints to intercept traffic.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1056", "Input Capture", ["TA0006", "TA0009"], "Capturing user input (keylogging).",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1539", "Steal Web Session Cookie", ["TA0006"], "Stealing browser session cookies.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1552", "Unsecured Credentials", ["TA0006"], "Finding credentials stored insecurely.",
             platforms=["Windows", "Linux", "macOS"]),

    # ── Discovery ───────────────────────────────────────────────
    Technique("T1087", "Account Discovery", ["TA0007"], "Enumerating system and domain accounts.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1087.002", "Domain Account", ["TA0007"], "Enumerating domain accounts.",
             is_subtechnique=True, parent_id="T1087", platforms=["Windows"]),
    Technique("T1082", "System Information Discovery", ["TA0007"], "Gathering system configuration info.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1083", "File and Directory Discovery", ["TA0007"], "Enumerating files and directories.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1046", "Network Service Discovery", ["TA0007"], "Scanning for network services.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1057", "Process Discovery", ["TA0007"], "Listing running processes.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1018", "Remote System Discovery", ["TA0007"], "Discovering remote systems on the network.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1049", "System Network Connections Discovery", ["TA0007"],
             "Enumerating network connections.", platforms=["Windows", "Linux", "macOS"]),
    Technique("T1016", "System Network Configuration Discovery", ["TA0007"],
             "Gathering network configuration details.", platforms=["Windows", "Linux", "macOS"]),
    Technique("T1482", "Domain Trust Discovery", ["TA0007"], "Enumerating domain trust relationships.",
             platforms=["Windows"]),
    Technique("T1069", "Permission Groups Discovery", ["TA0007"], "Discovering permission group settings.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1033", "System Owner/User Discovery", ["TA0007"], "Identifying the system owner.",
             platforms=["Windows", "Linux", "macOS"]),

    # ── Lateral Movement ────────────────────────────────────────
    Technique("T1021", "Remote Services", ["TA0008"], "Using remote services to move laterally.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1021.001", "Remote Desktop Protocol", ["TA0008"], "Using RDP for lateral movement.",
             is_subtechnique=True, parent_id="T1021", platforms=["Windows"]),
    Technique("T1021.002", "SMB/Windows Admin Shares", ["TA0008"], "Using SMB shares for lateral movement.",
             is_subtechnique=True, parent_id="T1021", platforms=["Windows"]),
    Technique("T1021.003", "DCOM", ["TA0008"], "Using DCOM for remote execution.",
             is_subtechnique=True, parent_id="T1021", platforms=["Windows"]),
    Technique("T1021.004", "SSH", ["TA0008"], "Using SSH for lateral movement.",
             is_subtechnique=True, parent_id="T1021", platforms=["Linux", "macOS"]),
    Technique("T1021.006", "Windows Remote Management", ["TA0008"], "Using WinRM for lateral movement.",
             is_subtechnique=True, parent_id="T1021", platforms=["Windows"]),
    Technique("T1570", "Lateral Tool Transfer", ["TA0008"], "Transferring tools between systems.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1210", "Exploitation of Remote Services", ["TA0008"],
             "Exploiting remote services for lateral movement.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1534", "Internal Spearphishing", ["TA0008"],
             "Spearphishing within the compromised environment.", platforms=["Windows", "Linux", "macOS"]),
    Technique("T1550", "Use Alternate Authentication Material", ["TA0005", "TA0008"],
             "Using non-standard auth like pass-the-hash.", platforms=["Windows"]),
    Technique("T1550.002", "Pass the Hash", ["TA0005", "TA0008"], "Authenticating with stolen NTLM hashes.",
             is_subtechnique=True, parent_id="T1550", platforms=["Windows"]),
    Technique("T1550.003", "Pass the Ticket", ["TA0005", "TA0008"],
             "Authenticating with stolen Kerberos tickets.",
             is_subtechnique=True, parent_id="T1550", platforms=["Windows"]),

    # ── Collection ──────────────────────────────────────────────
    Technique("T1560", "Archive Collected Data", ["TA0009"], "Compressing data before exfiltration.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1114", "Email Collection", ["TA0009"], "Collecting email from local or remote sources.",
             platforms=["Windows", "Google Workspace", "Office 365"]),
    Technique("T1005", "Data from Local System", ["TA0009"], "Collecting data from the local file system.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1039", "Data from Network Shared Drive", ["TA0009"],
             "Collecting data from network shares.", platforms=["Windows", "Linux", "macOS"]),
    Technique("T1113", "Screen Capture", ["TA0009"], "Capturing screenshots.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1119", "Automated Collection", ["TA0009"], "Using scripts to automatically collect data.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1530", "Data from Cloud Storage", ["TA0009"], "Accessing cloud storage for data.",
             platforms=["Azure AD", "Google Workspace", "AWS"]),

    # ── Command and Control ─────────────────────────────────────
    Technique("T1071", "Application Layer Protocol", ["TA0011"],
             "Using application layer protocols for C2.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1071.001", "Web Protocols", ["TA0011"], "Using HTTP/HTTPS for C2.",
             is_subtechnique=True, parent_id="T1071"),
    Technique("T1071.002", "File Transfer Protocols", ["TA0011"], "Using FTP for C2.",
             is_subtechnique=True, parent_id="T1071"),
    Technique("T1071.003", "Mail Protocols", ["TA0011"], "Using SMTP/POP3 for C2.",
             is_subtechnique=True, parent_id="T1071"),
    Technique("T1071.004", "DNS", ["TA0011"], "Using DNS for C2 communication.",
             is_subtechnique=True, parent_id="T1071"),
    Technique("T1105", "Ingress Tool Transfer", ["TA0011"], "Downloading additional tools to the target.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1573", "Encrypted Channel", ["TA0011"], "Using encryption for C2 communication.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1573.001", "Symmetric Cryptography", ["TA0011"], "Using symmetric encryption for C2.",
             is_subtechnique=True, parent_id="T1573"),
    Technique("T1573.002", "Asymmetric Cryptography", ["TA0011"], "Using asymmetric encryption for C2.",
             is_subtechnique=True, parent_id="T1573"),
    Technique("T1572", "Protocol Tunneling", ["TA0011"], "Tunneling C2 through legitimate protocols.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1090", "Proxy", ["TA0011"], "Using proxy servers for C2.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1090.002", "External Proxy", ["TA0011"], "Using external proxy services.",
             is_subtechnique=True, parent_id="T1090"),
    Technique("T1095", "Non-Application Layer Protocol", ["TA0011"],
             "Using non-application layer protocols (ICMP, UDP) for C2.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1568", "Dynamic Resolution", ["TA0011"], "Dynamically resolving C2 destinations.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1568.002", "Domain Generation Algorithms", ["TA0011"],
             "Using algorithms to generate C2 domains.",
             is_subtechnique=True, parent_id="T1568"),
    Technique("T1219", "Remote Access Software", ["TA0011"], "Using legitimate remote access tools for C2.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1102", "Web Service", ["TA0011"], "Using legitimate web services for C2.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1571", "Non-Standard Port", ["TA0011"], "Using uncommon ports for C2.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1008", "Fallback Channels", ["TA0011"], "Using backup C2 channels.",
             platforms=["Windows", "Linux", "macOS"]),

    # ── Exfiltration ────────────────────────────────────────────
    Technique("T1041", "Exfiltration Over C2 Channel", ["TA0010"], "Exfiltrating data over C2.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1048", "Exfiltration Over Alternative Protocol", ["TA0010"],
             "Using non-C2 protocols for exfiltration.", platforms=["Windows", "Linux", "macOS"]),
    Technique("T1567", "Exfiltration Over Web Service", ["TA0010"],
             "Using cloud storage or web services for exfiltration.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1567.002", "Exfiltration to Cloud Storage", ["TA0010"],
             "Uploading stolen data to cloud storage.",
             is_subtechnique=True, parent_id="T1567"),
    Technique("T1029", "Scheduled Transfer", ["TA0010"], "Exfiltrating data at scheduled intervals.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1537", "Transfer Data to Cloud Account", ["TA0010"],
             "Moving data to adversary-controlled cloud accounts.",
             platforms=["Azure AD", "AWS", "GCP"]),
    Technique("T1020", "Automated Exfiltration", ["TA0010"], "Using scripts to automate exfiltration.",
             platforms=["Windows", "Linux", "macOS"]),

    # ── Impact ──────────────────────────────────────────────────
    Technique("T1486", "Data Encrypted for Impact", ["TA0040"],
             "Encrypting data to cause disruption (ransomware).",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1490", "Inhibit System Recovery", ["TA0040"], "Deleting backups and shadow copies.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1489", "Service Stop", ["TA0040"], "Stopping critical services.",
             platforms=["Windows", "Linux"]),
    Technique("T1485", "Data Destruction", ["TA0040"], "Destroying data on target systems.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1491", "Defacement", ["TA0040"], "Modifying visual content for messaging.",
             platforms=["Windows", "Linux"]),
    Technique("T1499", "Endpoint Denial of Service", ["TA0040"], "Causing a DoS on endpoints.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1496", "Resource Hijacking", ["TA0040"], "Using victim resources (cryptomining).",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1531", "Account Access Removal", ["TA0040"], "Deleting or locking accounts.",
             platforms=["Windows", "Linux", "macOS"]),
    Technique("T1565", "Data Manipulation", ["TA0040"], "Inserting, modifying, or deleting data.",
             platforms=["Windows", "Linux", "macOS"]),
]

# ════════════════════════════════════════════════════════════════════
# GROUPS — Major Threat Actor Groups
# ════════════════════════════════════════════════════════════════════
GROUPS: List[Group] = [
    Group("G0016", "APT29", ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"],
          "Russian SVR-linked group targeting governments and tech companies.",
          ["T1566.001", "T1566.002", "T1078", "T1190", "T1059.001", "T1059.003",
           "T1003.001", "T1003.003", "T1003.006", "T1021.001", "T1021.002", "T1021.006",
           "T1053.005", "T1547.001", "T1071.001", "T1573.002", "T1105", "T1027",
           "T1070.001", "T1082", "T1087.002", "T1018", "T1005", "T1041",
           "T1055.001", "T1134", "T1098", "T1068", "T1562.001", "T1482"],
          ["S0154", "S0005", "S0085"], "Russia"),
    Group("G0007", "APT28", ["Fancy Bear", "STRONTIUM", "Forest Blizzard", "Sofacy"],
          "Russian GRU-linked group targeting government, military, and media.",
          ["T1566.001", "T1566.002", "T1190", "T1133", "T1078", "T1059.001",
           "T1059.003", "T1059.005", "T1003.001", "T1110.003", "T1539", "T1557",
           "T1071.001", "T1071.004", "T1573.001", "T1090.002", "T1105", "T1027",
           "T1036", "T1070.004", "T1082", "T1087", "T1005", "T1560", "T1041",
           "T1046", "T1053.005", "T1547.001", "T1204.001", "T1204.002"],
          ["S0154", "S0005"], "Russia"),
    Group("G0050", "APT32", ["OceanLotus", "Canvas Cyclone"],
          "Vietnamese group targeting private sector and foreign governments.",
          ["T1566.001", "T1204.002", "T1059.001", "T1059.003", "T1059.005",
           "T1059.007", "T1203", "T1547.001", "T1053.005", "T1071.001",
           "T1027", "T1036", "T1055", "T1082", "T1083", "T1057", "T1005",
           "T1105", "T1218.011", "T1140", "T1573.001"],
          [], "Vietnam"),
    Group("G0032", "Lazarus Group", ["HIDDEN COBRA", "Diamond Sleet", "Zinc"],
          "North Korean state-sponsored group conducting espionage and financial theft.",
          ["T1566.001", "T1189", "T1195", "T1059.001", "T1059.003", "T1059.006",
           "T1204.002", "T1547.001", "T1543.003", "T1078", "T1003.001",
           "T1071.001", "T1573.001", "T1105", "T1027", "T1055", "T1036",
           "T1082", "T1083", "T1057", "T1005", "T1041", "T1486", "T1490",
           "T1567.002", "T1568.002"],
          ["S0154"], "North Korea"),
    Group("G0096", "APT41", ["Wicked Panda", "Brass Typhoon"],
          "Chinese state-sponsored group conducting espionage and financial crime.",
          ["T1190", "T1133", "T1195", "T1078", "T1059.001", "T1059.003",
           "T1059.006", "T1053.005", "T1547.001", "T1543.003", "T1505.003",
           "T1003.001", "T1003.003", "T1110", "T1071.001", "T1105", "T1027",
           "T1055", "T1562.001", "T1082", "T1087", "T1046", "T1021.001",
           "T1021.002", "T1570", "T1005", "T1039", "T1560", "T1041"],
          ["S0154"], "China"),
    Group("G0010", "Turla", ["Venomous Bear", "Secret Blizzard", "Snake"],
          "Russian FSB-linked espionage group targeting governments and embassies.",
          ["T1566.001", "T1189", "T1059.001", "T1059.003", "T1059.005",
           "T1547.001", "T1053.005", "T1078", "T1003.001", "T1071.001",
           "T1071.004", "T1573.002", "T1090", "T1105", "T1027", "T1036",
           "T1055", "T1070", "T1082", "T1083", "T1087", "T1005", "T1041"],
          [], "Russia"),
    Group("G0114", "Chimera", [],
          "Chinese threat group targeting semiconductor and airline industries.",
          ["T1078", "T1133", "T1059.001", "T1059.003", "T1003.001", "T1003.003",
           "T1558.003", "T1021.001", "T1021.002", "T1071.001", "T1105",
           "T1082", "T1087.002", "T1482", "T1005", "T1560"],
          [], "China"),
    Group("G0045", "menuPass", ["APT10", "Stone Panda", "Red Apollo"],
          "Chinese group targeting managed IT service providers for supply chain access.",
          ["T1566.001", "T1199", "T1059.001", "T1059.003", "T1053.005",
           "T1547.001", "T1078", "T1003.001", "T1003.003", "T1071.001",
           "T1105", "T1027", "T1082", "T1087", "T1049", "T1016",
           "T1005", "T1039", "T1560", "T1041"],
          [], "China"),
    Group("G0059", "Magic Hound", ["APT35", "Charming Kitten", "Mint Sandstorm"],
          "Iranian group targeting academic, government, and media sectors.",
          ["T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
           "T1059.005", "T1204.001", "T1204.002", "T1547.001", "T1053.005",
           "T1003.001", "T1110", "T1071.001", "T1105", "T1027", "T1082",
           "T1087", "T1005", "T1041", "T1567.002"],
          [], "Iran"),
    Group("G0027", "Threat Group-3390", ["APT27", "Emissary Panda"],
          "Chinese group targeting technology, energy, and aerospace sectors.",
          ["T1190", "T1078", "T1059.001", "T1059.003", "T1505.003",
           "T1547.001", "T1053.005", "T1003.001", "T1003.003", "T1071.001",
           "T1105", "T1027", "T1082", "T1087", "T1046", "T1021.002",
           "T1005", "T1560", "T1041"],
          [], "China"),
]

# ════════════════════════════════════════════════════════════════════
# SOFTWARE — Major Malware and Tools
# ════════════════════════════════════════════════════════════════════
SOFTWARE: List[Software] = [
    Software("S0154", "Cobalt Strike", "tool",
             "Commercial adversary simulation framework widely abused by threat actors.",
             ["T1059.001", "T1059.003", "T1071.001", "T1071.004", "T1573.002",
              "T1105", "T1055.001", "T1027", "T1036", "T1070.004",
              "T1003.001", "T1003.003", "T1134", "T1547.001", "T1053.005",
              "T1021.002", "T1021.006", "T1570", "T1550.002",
              "T1082", "T1087", "T1057", "T1049", "T1018",
              "T1005", "T1560", "T1041", "T1572", "T1090"],
             ["Windows", "Linux"]),
    Software("S0005", "Mimikatz", "tool",
             "Credential dumping tool for extracting passwords, hashes, and Kerberos tickets.",
             ["T1003.001", "T1003.003", "T1003.006", "T1558.003", "T1550.002",
              "T1550.003", "T1134", "T1098"],
             ["Windows"]),
    Software("S0085", "Empire", "tool",
             "PowerShell-based post-exploitation framework.",
             ["T1059.001", "T1059.005", "T1071.001", "T1105", "T1027",
              "T1055", "T1003.001", "T1547.001", "T1053.005",
              "T1082", "T1087", "T1057", "T1005"],
             ["Windows", "macOS", "Linux"]),
    Software("S0029", "PsExec", "tool",
             "Microsoft Sysinternals tool for remote command execution.",
             ["T1021.002", "T1569.002", "T1570"],
             ["Windows"]),
    Software("S0039", "Impacket", "tool",
             "Collection of Python classes for working with network protocols.",
             ["T1021.002", "T1021.003", "T1021.006", "T1003.003", "T1003.006",
              "T1558.003", "T1550.002", "T1047"],
             ["Windows", "Linux"]),
    Software("S0552", "AdFind", "tool",
             "Active Directory query tool used for enumeration.",
             ["T1087.002", "T1482", "T1069.002", "T1018"],
             ["Windows"]),
    Software("S0357", "WannaCry", "malware",
             "Ransomware that spread via EternalBlue SMB exploit.",
             ["T1486", "T1490", "T1489", "T1210", "T1021.002"],
             ["Windows"]),
    Software("S0446", "Ryuk", "malware",
             "Ransomware operated by WIZARD SPIDER targeting enterprises.",
             ["T1486", "T1490", "T1489", "T1059.001", "T1021.002", "T1570",
              "T1082", "T1083", "T1057", "T1547.001"],
             ["Windows"]),
    Software("S0650", "QakBot", "malware",
             "Banking trojan turned initial access broker for ransomware gangs.",
             ["T1566.001", "T1204.002", "T1059.001", "T1059.005", "T1547.001",
              "T1053.005", "T1055", "T1071.001", "T1105", "T1003.001",
              "T1082", "T1087", "T1057"],
             ["Windows"]),
    Software("S0600", "Emotet", "malware",
             "Modular trojan primarily spread via spam email campaigns.",
             ["T1566.001", "T1204.002", "T1059.001", "T1059.005", "T1547.001",
              "T1053.005", "T1071.001", "T1105", "T1027", "T1055",
              "T1003.001", "T1082", "T1087"],
             ["Windows"]),
]

# ════════════════════════════════════════════════════════════════════
# MITIGATIONS
# ════════════════════════════════════════════════════════════════════
MITIGATIONS: List[Mitigation] = [
    Mitigation("M1049", "Antivirus/Antimalware", "Use signatures and heuristics to detect malware.",
               ["T1566", "T1059", "T1204"]),
    Mitigation("M1032", "Multi-factor Authentication", "Use MFA to reduce credential theft impact.",
               ["T1078", "T1110", "T1133"]),
    Mitigation("M1027", "Password Policies", "Set and enforce secure password policies.",
               ["T1078", "T1110", "T1003"]),
    Mitigation("M1026", "Privileged Account Management", "Limit and audit privileged accounts.",
               ["T1078", "T1003", "T1059"]),
    Mitigation("M1030", "Network Segmentation", "Segment networks to limit lateral movement.",
               ["T1190", "T1133", "T1021"]),
    Mitigation("M1031", "Network Intrusion Prevention", "Use IDS/IPS to detect and block intrusions.",
               ["T1566", "T1071", "T1190"]),
    Mitigation("M1051", "Update Software", "Keep software updated to patch vulnerabilities.",
               ["T1190", "T1203", "T1210"]),
    Mitigation("M1017", "User Training", "Train users to recognize social engineering.",
               ["T1566", "T1204", "T1598"]),
    Mitigation("M1035", "Limit Access to Resource Over Network", "Restrict network access to resources.",
               ["T1133", "T1021"]),
    Mitigation("M1054", "Software Configuration", "Configure software to reduce attack surface.",
               ["T1566", "T1059"]),
    Mitigation("M1038", "Execution Prevention", "Block execution of unauthorized software.",
               ["T1059", "T1204", "T1218"]),
    Mitigation("M1042", "Disable or Remove Feature or Program", "Remove unnecessary features.",
               ["T1059", "T1047", "T1218"]),
    Mitigation("M1043", "Credential Access Protection", "Protect credential stores from access.",
               ["T1003"]),
    Mitigation("M1036", "Account Use Policies", "Configure account lockout and other policies.",
               ["T1110"]),
    Mitigation("M1050", "Exploit Protection", "Use exploit mitigation technologies.",
               ["T1190", "T1203", "T1068"]),
    Mitigation("M1048", "Application Isolation and Sandboxing", "Isolate high-risk applications.",
               ["T1190", "T1203"]),
]


# ════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ════════════════════════════════════════════════════════════════════
def get_tactic_by_id(tactic_id: str) -> Optional[Tactic]:
    return next((t for t in TACTICS if t.id == tactic_id), None)

def get_technique_by_id(tech_id: str) -> Optional[Technique]:
    return next((t for t in TECHNIQUES if t.id == tech_id), None)

def get_techniques_by_tactic(tactic_id: str) -> List[Technique]:
    return [t for t in TECHNIQUES if tactic_id in t.tactic_ids]

def get_parent_techniques_by_tactic(tactic_id: str) -> List[Technique]:
    return [t for t in TECHNIQUES if tactic_id in t.tactic_ids and not t.is_subtechnique]

def get_subtechniques(parent_id: str) -> List[Technique]:
    return [t for t in TECHNIQUES if t.parent_id == parent_id]

def get_group_by_id(group_id: str) -> Optional[Group]:
    return next((g for g in GROUPS if g.id == group_id), None)

def get_group_by_name(name: str) -> Optional[Group]:
    name_lower = name.lower()
    for g in GROUPS:
        if g.name.lower() == name_lower or any(a.lower() == name_lower for a in g.aliases):
            return g
    return None

def get_groups_using_technique(tech_id: str) -> List[Group]:
    return [g for g in GROUPS if tech_id in g.technique_ids]

def get_software_by_id(sw_id: str) -> Optional[Software]:
    return next((s for s in SOFTWARE if s.id == sw_id), None)

def get_software_using_technique(tech_id: str) -> List[Software]:
    return [s for s in SOFTWARE if tech_id in s.technique_ids]

def get_mitigations_for_technique(tech_id: str) -> List[Mitigation]:
    return [m for m in MITIGATIONS if tech_id in m.technique_ids]

def get_tactic_technique_matrix() -> Dict[str, List[Technique]]:
    """Returns the full ATT&CK matrix: {tactic_id: [techniques]}"""
    matrix = {}
    for tactic in TACTICS:
        matrix[tactic.id] = get_parent_techniques_by_tactic(tactic.id)
    return matrix

def search_techniques(query: str) -> List[Technique]:
    """Search techniques by name, ID, or description."""
    q = query.lower()
    return [t for t in TECHNIQUES if q in t.id.lower() or q in t.name.lower() or q in t.description.lower()]
