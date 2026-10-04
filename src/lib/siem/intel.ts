import type { Intel, MitreTechnique, SourceKind } from "./types";

export const LAB_START = "2026-10-01T00:00:00.000Z";
export const LAB_END = "2026-10-02T17:00:00.000Z";
export const COMPANY = "Meridian Capital";
export const LAB_NAME = "Blackridge SIEM Lab";

export const SOURCES: Record<
  SourceKind,
  {
    label: string;
    product: string;
    host: string;
    index: string;
    dest: string;
    description: string;
  }
> = {
  system: {
    label: "System logs",
    product: "Windows Event Log + Sysmon",
    host: "WEF-01 / MERIDIAN-DC01",
    index: "winevent",
    dest: "WinEventLog:Security, Sysmon",
    description:
      "Forwarded Windows Security, System, and Sysmon operational logs from workstations, the finance file server, and the domain controller.",
  },
  honeypot: {
    label: "Honeypot",
    product: "Cowrie SSH/Telnet",
    host: "HPOT-SSH-01",
    index: "honeypot",
    dest: "cowrie",
    description:
      "Internet-facing Cowrie medium-interaction honeypot in the DMZ (10.50.1.20). Intentionally weak credentials, session replay enabled.",
  },
  firewall: {
    label: "Firewall",
    product: "Palo Alto PA-3220",
    host: "FW-EDGE-01",
    index: "network",
    dest: "pan:traffic, pan:threat",
    description:
      "Edge NGFW traffic, threat, and DNS logs covering north-south internet and east-west rules between DMZ, users, and servers.",
  },
};

export const MITRE: Record<string, MitreTechnique> = {
  "T1110.001": { id: "T1110.001", name: "Password Guessing", tactic: "Credential Access" },
  T1078: { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
  T1046: { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
  "T1059.004": { id: "T1059.004", name: "Unix Shell", tactic: "Execution" },
  "T1566.001": { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access" },
  "T1204.002": { id: "T1204.002", name: "Malicious File", tactic: "Execution" },
  "T1059.001": { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
  T1105: { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
  T1490: { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
  T1486: { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
  T1080: { id: "T1080", name: "Taint Shared Content", tactic: "Lateral Movement" },
  "T1036.005": { id: "T1036.005", name: "Match Legitimate Name or Location", tactic: "Defense Evasion" },
  "T1071.004": { id: "T1071.004", name: "DNS", tactic: "Command and Control" },
  "T1048.003": { id: "T1048.003", name: "Exfiltration Over Unencrypted Non-C2 Protocol", tactic: "Exfiltration" },
  "T1567.002": { id: "T1567.002", name: "Exfiltration to Cloud Storage", tactic: "Exfiltration" },
  T1020: { id: "T1020", name: "Automated Exfiltration", tactic: "Exfiltration" },
  "T1078.002": { id: "T1078.002", name: "Domain Accounts", tactic: "Persistence" },
  "T1558.003": { id: "T1558.003", name: "Kerberoasting", tactic: "Credential Access" },
  "T1003.006": { id: "T1003.006", name: "DCSync", tactic: "Credential Access" },
  "T1136.002": { id: "T1136.002", name: "Create Domain Account", tactic: "Persistence" },
  "T1021.001": { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "Lateral Movement" },
  "T1021.002": { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" },
};

export const INTEL: Record<string, Intel> = {
  "185.220.101.47": {
    verdict: "malicious",
    asn: "AS205100",
    org: "TOR exit",
    country: "DE",
    note: "Known TOR exit node. High volume SSH brute force in last 30 days.",
  },
  "185.220.102.8": {
    verdict: "malicious",
    asn: "AS205100",
    org: "TOR exit",
    country: "NL",
    note: "Companion TOR exit used as secondary brute-force source.",
  },
  "91.215.85.22": {
    verdict: "malicious",
    asn: "AS213373",
    org: "Bulletproof VPS",
    country: "RU",
    note: "Payload host for Ledgerlock ransomware. Listed on three commercial threat feeds.",
  },
  "upd-cdn.services": {
    verdict: "malicious",
    note: "Domain registered 28 Sep 2026. No web content. High-entropy DNS TXT pattern.",
  },
  "45.142.150.19": {
    verdict: "suspicious",
    asn: "AS210848",
    org: "Cheap VPS",
    country: "MD",
    note: "VPN source for d.park — impossible travel from New York in 38 minutes.",
  },
  "32.87.12.4": {
    verdict: "benign",
    asn: "AS2686",
    org: "AT&T",
    country: "US",
    note: "Residential/office egress normally used by d.park in Manhattan.",
  },
};

export const HASHES = {
  ledgerlock:
    "a4f31c8e9b0d77e2c1f5aa90b3d4e6f8123456789abcdeff0011223344556677",
  updater: "c91e0b44aa18d2f0e7c3b8a1567d0e21aa44bb9910cc22dd33ee44ff55aa6677",
};
