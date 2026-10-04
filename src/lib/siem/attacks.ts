import type { Attack } from "./types";
import { HASHES } from "./intel";

export const ATTACKS: Attack[] = [
  {
    id: "night-latch",
    code: "BR-2026-0141",
    name: "Night Latch",
    headline: "TOR brute force cracked the DMZ honeypot, then the firewall stopped the pivot.",
    severity: "medium",
    status: "contained",
    started: "2026-10-01T01:12:04.000Z",
    ended: "2026-10-01T02:41:18.000Z",
    mttd: "11 min",
    mttr: "Contained by design",
    sources: ["honeypot", "firewall"],
    assets: ["HPOT-SSH-01 (10.50.1.20)", "FW-EDGE-01"],
    mitre: ["T1110.001", "T1078", "T1046", "T1059.004"],
    iocs: [
      { type: "ip", value: "185.220.101.47", context: "Primary TOR exit, 4,218 SSH attempts" },
      { type: "ip", value: "185.220.102.8", context: "Secondary TOR exit" },
      { type: "credential", value: "admin / Summer2024!", context: "Successful Cowrie login" },
    ],
    story: [
      "At 01:12 UTC a TOR exit (185.220.101.47) began an SSH password-guessing campaign against the internet-facing Cowrie honeypot in the DMZ.",
      "Over 86 minutes the sensor recorded 4,218 failures across common usernames. At 02:37 the pair admin / Summer2024! succeeded — a password that matches a weak seasonal pattern still present in Meridian AD.",
      "The operator enumerated the host, fetched a staging binary, and probed 10.10.0.0/16. East-west firewall policy dropped the pivot. No production asset was touched.",
      "The honeypot did its job. The residual risk is password reuse: the same seasonal pattern is a viable spray against VPN and service accounts.",
    ],
    businessImpact:
      "No production outage. Intelligence value is high: this is the same password class later reused in Ticket Forge. Treat as a free red-team against internet SSH.",
    execFinding:
      "Internet brute force is constant. The honeypot absorbed it, but Summer2024! is a live password pattern in the estate. If that spray had hit the VPN instead of Cowrie, this would have been a breach.",
    recommendations: [
      {
        horizon: "immediate",
        owner: "Identity",
        title: "Ban seasonal passwords and spray-test AD",
        detail: "Force rotation of accounts matching Summer/Winter/Fall+year patterns. Run a password audit against NTDS.",
      },
      {
        horizon: "30d",
        owner: "SOC",
        title: "Page on honeypot success, not just volume",
        detail: "A successful Cowrie login should be a P2 page. Volume alerts without success correlation were delayed 11 minutes.",
      },
      {
        horizon: "90d",
        owner: "Network",
        title: "Keep the decoy, add two more",
        detail: "Expand deception to RDP and an internal file-share honeypot so Ticket Forge-style east-west movement is baited.",
      },
    ],
  },
  {
    id: "ledgerlock",
    code: "BR-2026-0142",
    name: "Ledgerlock",
    headline: "A finance workstation opened a macro invoice and ransomware hit the Q3 close share.",
    severity: "critical",
    status: "eradicated",
    started: "2026-10-01T09:04:41.000Z",
    ended: "2026-10-01T09:22:08.000Z",
    mttd: "8 min",
    mttr: "14 min to isolate",
    sources: ["system", "firewall"],
    assets: ["FIN-WS-14 (j.chen)", "FIN-FS-01 (finance share)", "FW-EDGE-01"],
    mitre: ["T1566.001", "T1204.002", "T1059.001", "T1105", "T1490", "T1486", "T1080"],
    iocs: [
      { type: "hash", value: HASHES.ledgerlock, context: "upd.exe payload" },
      { type: "ip", value: "91.215.85.22", context: "Payload and C2" },
      { type: "file", value: "Q3_Invoice_ACH.xlsm", context: "Phishing attachment" },
      { type: "file", value: "LEDGERLOCK_README.txt", context: "Ransom note" },
    ],
    story: [
      "At 09:04 analyst Jia Chen opened Q3_Invoice_ACH.xlsm from an external sender spoofing a clearing vendor. WINWORD spawned encoded PowerShell (Sysmon 1 / Event 4688).",
      "PowerShell pulled upd.exe from 91.215.85.22. The binary deleted volume shadow copies, disabled recovery, and encrypted local plus mapped finance-share files with the .ledgerlock extension.",
      "The firewall logged the C2 callback and a burst of SMB from FIN-WS-14 to FIN-FS-01. East-west SMB is permitted for the finance VLAN — that is how Q3 close files were reached.",
      "Isolation at 09:18 stopped further encryption. Approximately 4,200 files were affected. There is no EDR telemetry in this estate; detection relied on Sysmon plus firewall.",
    ],
    businessImpact:
      "Q3 close delayed. Estimated operational impact $1.8–2.4M (restated close, overtime, vendor stand-by). Ransom was not paid. Restore from 30 Sep backup is in progress.",
    execFinding:
      "A single macro-enabled invoice bypassed mail controls and, because finance workstations can write the close share, encryption left the endpoint in minutes. No EDR was present to kill the process.",
    recommendations: [
      {
        horizon: "immediate",
        owner: "IT Ops",
        title: "Reimage FIN-WS-14 and restore FIN-FS-01 from 30 Sep",
        detail: "Do not reconnect the workstation. Verify backup integrity before overlaying the share. Rotate j.chen credentials.",
      },
      {
        horizon: "immediate",
        owner: "Network",
        title: "Block 91.215.85.22 and the Ledgerlock hash estate-wide",
        detail: "Sinkhole at DNS and deny at FW-EDGE-01. Push the SHA-256 to any existing AV hash list.",
      },
      {
        horizon: "30d",
        owner: "IT Ops",
        title: "EDR on 100% of endpoints, starting with finance",
        detail: "Sysmon is not a substitute. Require behavioral ransomware canaries and automatic isolation.",
      },
      {
        horizon: "90d",
        owner: "Finance / IT",
        title: "Make the close share append-only during freeze",
        detail: "Workstations should not have modify rights on the canonical close share. Use a controlled jump or immutable object storage.",
      },
    ],
  },
  {
    id: "silent-siphon",
    code: "BR-2026-0143",
    name: "Silent Siphon",
    headline: "Six hours of DNS tunneling quietly lifted 42,118 employee records off an HR laptop.",
    severity: "high",
    status: "contained",
    started: "2026-10-01T11:02:19.000Z",
    ended: "2026-10-01T16:48:33.000Z",
    mttd: "5 h 12 min",
    mttr: "Still scoping",
    sources: ["firewall", "system"],
    assets: ["HR-LAP-07 (r.okonkwo)", "HRIS export staging"],
    mitre: ["T1036.005", "T1071.004", "T1048.003", "T1567.002", "T1020"],
    iocs: [
      { type: "domain", value: "upd-cdn.services", context: "Newly registered DNS tunnel parent" },
      { type: "hash", value: HASHES.updater, context: "AppData\\Roaming\\updater.exe" },
      { type: "ip", value: "185.199.108.153", context: "HTTPS backup exfil path (cloud CDN front)" },
    ],
    story: [
      "From 11:02 an unsigned updater.exe in the user profile of r.okonkwo issued DNS TXT queries to randomised subdomains of upd-cdn.services every ~30 seconds.",
      "Firewall DNS logs show 14.2 GB of TXT payload over six hours — far above the estate baseline of <12 MB/host/day. A parallel HTTPS POST channel opened after 15:40.",
      "The process tree masqueraded under a svchost-style name. Sysmon recorded the parent as updater.exe with no Authenticode signature. The host had exported a full HRIS payroll dump the previous afternoon.",
      "Detection was slow because DNS is allowed any-any and there is no volume baseline on TXT. Data types include SSN, bank account, and home address for 42,118 employees and contractors.",
    ],
    businessImpact:
      "Likely reportable under state breach statutes and, for EU contractors, GDPR. Counsel estimates notification, credit-monitoring, and regulatory exposure in the $2–10M band, excluding class-action risk.",
    execFinding:
      "We lost people data because DNS was trusted. The laptop looked healthy. The firewall saw the volume and had no correlation rule. This is a disclosure event, not only a technical incident.",
    recommendations: [
      {
        horizon: "immediate",
        owner: "Legal / HR / CISO",
        title: "Stand up the breach-notification cell",
        detail: "Preserve HR-LAP-07. Confirm record count and data elements. Do not wait on full forensics to start the legal clock.",
      },
      {
        horizon: "immediate",
        owner: "Network",
        title: "Sinkhole upd-cdn.services and alert on TXT volume",
        detail: "Emergency DNS RPZ. Threshold: >50 TXT queries/host/hour or TXT bytes >5 MB/hour.",
      },
      {
        horizon: "30d",
        owner: "Security engineering",
        title: "DLP on DNS and HTTPS for HR/Finance VLANs",
        detail: "Inspect and block encoded payloads. Require DoH only via the enterprise resolver.",
      },
      {
        horizon: "90d",
        owner: "HR / Data",
        title: "Stop full HRIS dumps to laptops",
        detail: "Payroll extracts stay in a governed warehouse. No local CSV of the whole population.",
      },
    ],
  },
  {
    id: "ticket-forge",
    code: "BR-2026-0144",
    name: "Ticket Forge",
    headline: "Impossible-travel VPN, Kerberoasting, then a new Domain Admin — this is a forest-level event.",
    severity: "critical",
    status: "active",
    started: "2026-10-01T14:18:06.000Z",
    ended: "2026-10-01T15:06:44.000Z",
    mttd: "19 min",
    mttr: "Incomplete — krbtgt not yet rotated",
    sources: ["system", "firewall"],
    assets: ["VPN-GW", "FIN-WS-14", "MERIDIAN-DC01", "account svc_backup$"],
    mitre: ["T1078.002", "T1558.003", "T1003.006", "T1136.002", "T1021.001", "T1021.002"],
    iocs: [
      { type: "ip", value: "45.142.150.19", context: "Moldova VPS VPN source for d.park" },
      { type: "account", value: "MERIDIAN\\SQLService", context: "Kerberoasted SPN, etype 0x17" },
      { type: "account", value: "MERIDIAN\\svc_backup$", context: "Rogue Domain Admin created 14:52" },
    ],
    story: [
      "At 14:18 the VPN accepted d.park from 45.142.150.19 (Moldova). The same account had a 4624 from 32.87.12.4 (New York) at 13:40 — 38 minutes, physically impossible.",
      "From FIN-WS-14 (already tainted by Ledgerlock) the operator requested RC4 Kerberos TGS tickets for SQLService and HTTP/intranet (Event 4769, TicketEncryptionType 0x17). That is Kerberoasting.",
      "At 14:48 MERIDIAN-DC01 logged Directory Service replication access — DCSync of NTDS. At 14:52 a new account svc_backup$ was created and dropped into Domain Admins. RDP to the DC followed.",
      "SOC disabled the rogue account at 15:06. krbtgt has not been double-rotated. Assume golden-ticket capability until that completes. This incident is still ACTIVE.",
    ],
    businessImpact:
      "Domain compromise means every identity is untrusted until krbtgt rotation and a forest recovery decision. Residual attacker access could re-enter finance, HR, or SWIFT-adjacent systems. This is the board-level event.",
    execFinding:
      "An attacker who already had a foothold on a finance PC used a stolen VPN session, roasted a service account that still allowed RC4, and minted a Domain Admin. Until krbtgt is rotated twice, they may still hold a golden ticket.",
    recommendations: [
      {
        horizon: "immediate",
        owner: "Identity / CISO",
        title: "Double-rotate krbtgt and every Domain Admin",
        detail: "Disable svc_backup$ (done). Reset DA passwords. Rotate krbtgt twice 10+ hours apart. Kill all TGTs. Treat this as AD disaster recovery, not a routine reset.",
      },
      {
        horizon: "immediate",
        owner: "Network / SOC",
        title: "Revoke the Moldova VPN session and require MFA step-up",
        detail: "Block 45.142.150.19. Impossible-travel should hard-fail, not alert. d.park password reset and hardware-key MFA.",
      },
      {
        horizon: "30d",
        owner: "Identity",
        title: "Disable RC4 Kerberos; AES-only",
        detail: "SQLService and every other SPN must not be roastable with 0x17. Group Managed Service Accounts. No user-level SPN on high-privilege accounts.",
      },
      {
        horizon: "90d",
        owner: "CISO",
        title: "Tier-0 PAW model — DA never logs on from FIN-WS-14",
        detail: "Workstations in finance must not talk RPC/445 to DCs. Privileged workstations only. This path is what turned ransomware into forest compromise.",
      },
    ],
  },
];

export const ATTACK_BY_ID = Object.fromEntries(ATTACKS.map((a) => [a.id, a]));
