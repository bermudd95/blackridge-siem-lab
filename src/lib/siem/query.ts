import type { SiemEvent, SourceKind } from "./types";

export type ParsedQuery = {
  fields: Record<string, string>;
  terms: string[];
  excluded: string[];
};

const FIELD_ALIASES: Record<string, keyof SiemEvent | "source"> = {
  source: "source",
  sourcetype: "sourcetype",
  host: "host",
  index: "index",
  user: "user",
  src_ip: "srcIp",
  src: "srcIp",
  dest_ip: "destIp",
  dest: "destIp",
  dest_port: "destPort",
  dport: "destPort",
  action: "action",
  severity: "severity",
  eventcode: "eventCode",
  process: "process",
  incident: "incidentId",
  app: "app",
};

export function parseQuery(input: string): ParsedQuery {
  const fields: Record<string, string> = {};
  const terms: string[] = [];
  const excluded: string[] = [];
  const re = /(?:(\w+)=(?:"([^"]*)"|(\S+)))|(?:"([^"]+)")|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(input.trim()))) {
    if (m[1]) {
      fields[m[1].toLowerCase()] = (m[2] ?? m[3] ?? "").toLowerCase();
    } else {
      const tok = (m[4] ?? m[5] ?? "").trim();
      if (!tok) continue;
      if (tok.startsWith("-") && tok.length > 1) excluded.push(tok.slice(1).toLowerCase());
      else terms.push(tok.toLowerCase());
    }
  }
  return { fields, terms, excluded };
}

function fieldValue(e: SiemEvent, key: string): string {
  const mapped = FIELD_ALIASES[key];
  if (!mapped) return "";
  const v = e[mapped as keyof SiemEvent];
  if (v == null) return "";
  return String(v).toLowerCase();
}

export function matchEvent(e: SiemEvent, q: ParsedQuery): boolean {
  for (const [k, v] of Object.entries(q.fields)) {
    if (k === "index" && v === "*") continue;
    const got = fieldValue(e, k);
    if (!got.includes(v)) return false;
  }
  const hay = [
    e.raw,
    e.host,
    e.user,
    e.srcIp,
    e.destIp,
    e.process,
    e.action,
    e.incidentId,
    e.sourcetype,
    e.eventCode,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  for (const t of q.terms) {
    if (!hay.includes(t)) return false;
  }
  for (const t of q.excluded) {
    if (hay.includes(t)) return false;
  }
  return true;
}

export function searchEvents(events: SiemEvent[], query: string): SiemEvent[] {
  const trimmed = query.trim();
  if (!trimmed || trimmed === "*" || trimmed === "index=*") return events;
  const parsed = parseQuery(trimmed);
  return events.filter((e) => matchEvent(e, parsed));
}

export function fieldTop(
  events: SiemEvent[],
  field: "source" | "sourcetype" | "host" | "user" | "srcIp" | "severity" | "action",
  limit = 6,
) {
  const counts = new Map<string, number>();
  for (const e of events) {
    const v = e[field];
    if (v == null || v === "") continue;
    const key = String(v);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([value, count]) => ({ value, count }));
}

export const SAVED_SEARCHES = [
  { label: "All indexed", query: "index=*" },
  { label: "Honeypot success", query: "source=honeypot action=success" },
  { label: "Encoded PowerShell", query: "EventCode=4688 powershell" },
  { label: "DNS TXT volume", query: "dest_port=53 qtype=TXT" },
  { label: "Kerberoast RC4", query: "EventCode=4769 0x17" },
  { label: "Notables", query: "severity=critical" },
];

export function formatTs(iso: string) {
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

export function formatTsShort(iso: string) {
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

export const SOURCE_LABEL: Record<SourceKind, string> = {
  system: "system",
  honeypot: "honeypot",
  firewall: "firewall",
};
