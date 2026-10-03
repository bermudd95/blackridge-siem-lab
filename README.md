# Blackridge SIEM Lab

Interactive Splunk-style SIEM lab for **Meridian Capital**. Three collectors feed a searchable index; four campaigns were captured on 1 October 2026; the briefing is written for executives.

## Data sources

- **System logs** — Windows Event Log + Sysmon (workstations, finance file server, domain controller)
- **Honeypot** — Cowrie SSH in the DMZ (`HPOT-SSH-01`)
- **Firewall** — Palo Alto PA-3220 traffic, threat, and DNS (`FW-EDGE-01`)

## Captured attacks

| Code | Name | Story |
| --- | --- | --- |
| BR-2026-0141 | Night Latch | TOR brute force cracked the honeypot; east-west pivot was denied |
| BR-2026-0142 | Ledgerlock | Macro invoice → encoded PowerShell → ransomware on the Q3 close share |
| BR-2026-0143 | Silent Siphon | Six hours of DNS TXT tunneling; 42,118 employee records |
| BR-2026-0144 | Ticket Forge | Impossible-travel VPN, Kerberoasting, DCSync, rogue Domain Admin |

Telemetry is **synthetic training data**. It is not a production investigation.

## Run locally

```bash
npm install
npm run dev
```

Open [http://localhost:8080](http://localhost:8080).

```bash
npm run typecheck
npm run build
```

## What to try

- **Overview** — KPIs, volume by source, then replay a campaign and watch the live index catch it
- **Search** — SPL-style filters (`source=honeypot action=success`, `EventCode=4688 powershell`, `EventCode=4769 0x17`)
- **Incidents** — timeline, ATT&CK, IOCs, analyst notes
- **Briefing** — TLP:AMBER board paper with this-week / 30-day / 90-day recommendations (print or save as PDF)

## Stack

TanStack Start, React 19, Tailwind v4, Recharts.
