export type SourceKind = "system" | "honeypot" | "firewall";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type SiemEvent = {
  id: string;
  ts: string;
  source: SourceKind;
  sourcetype: string;
  index: string;
  host: string;
  severity: Severity;
  raw: string;
  action?: string;
  user?: string;
  srcIp?: string;
  destIp?: string;
  destPort?: number;
  srcPort?: number;
  eventCode?: string;
  process?: string;
  bytesOut?: number;
  bytesIn?: number;
  app?: string;
  incidentId?: string;
  mitre?: string[];
  notable?: boolean;
};

export type MitreTechnique = {
  id: string;
  name: string;
  tactic: string;
};

export type AttackStatus = "contained" | "active" | "eradicated";

export type Recommendation = {
  horizon: "immediate" | "30d" | "90d";
  owner: string;
  title: string;
  detail: string;
};

export type Attack = {
  id: string;
  code: string;
  name: string;
  headline: string;
  severity: Severity;
  status: AttackStatus;
  started: string;
  ended: string;
  mttd: string;
  mttr: string;
  sources: SourceKind[];
  assets: string[];
  mitre: string[];
  iocs: { type: string; value: string; context: string }[];
  story: string[];
  businessImpact: string;
  execFinding: string;
  recommendations: Recommendation[];
};

export type Intel = {
  verdict: "malicious" | "suspicious" | "benign";
  asn?: string;
  org?: string;
  country?: string;
  note: string;
};
