import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip as RTooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ArrowRight } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { HuntPanel } from "@/components/siem/hunt-panel";
import { SeverityBadge } from "@/components/siem/severity-badge";
import { ATTACKS } from "@/lib/siem/attacks";
import { EVENTS, hourlyVolume, notables, severityStats, sourceStats } from "@/lib/siem/events";
import { formatTsShort } from "@/lib/siem/query";
import { MITRE } from "@/lib/siem/intel";
import { SOURCES } from "@/lib/siem/intel";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  const sev = severityStats();
  const src = sourceStats();
  const volume = hourlyVolume().map((h) => ({
    ...h,
    label: formatTsShort(h.hour).slice(0, 5),
  }));
  const notableCount = notables().length;
  const techniques = [...new Set(ATTACKS.flatMap((a) => a.mitre))];

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-6 md:px-8 md:py-8">
      <header className="flex flex-col gap-2">
        <p className="text-[11px] font-medium uppercase tracking-[0.18em] text-muted-foreground">
          Meridian Capital · Security operations
        </p>
        <h1 className="text-2xl font-medium tracking-tight md:text-3xl">SOC overview</h1>
        <p className="max-w-2xl text-sm text-muted-foreground">
          Blackridge is ingesting Windows/Sysmon system logs, a Cowrie SSH honeypot, and Palo Alto firewall
          telemetry. Four campaigns hit the estate on 1 October 2026. Investigate them, then open the executive
          briefing.
        </p>
      </header>

      <section className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Kpi label="Events indexed" value={EVENTS.length} hint="lab window" />
        <Kpi label="Notable events" value={notableCount} hint="correlated" />
        <Kpi label="Sources" value="3 / 3" hint="healthy" />
        <Kpi label="Open incidents" value={ATTACKS.filter((a) => a.status !== "eradicated").length} hint="of 4 captured" />
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Indexed volume by source</CardTitle>
          </CardHeader>
          <CardContent className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={volume} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="var(--color-border)" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: "var(--color-muted-foreground)", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "var(--color-muted-foreground)", fontSize: 10 }} axisLine={false} tickLine={false} />
                <RTooltip
                  contentStyle={{
                    background: "var(--color-popover)",
                    border: "1px solid var(--color-border)",
                    fontSize: 12,
                  }}
                />
                <Area type="monotone" dataKey="firewall" stackId="1" stroke="var(--color-medium)" fill="var(--color-medium)" fillOpacity={0.35} />
                <Area type="monotone" dataKey="system" stackId="1" stroke="var(--color-primary)" fill="var(--color-primary)" fillOpacity={0.25} />
                <Area type="monotone" dataKey="honeypot" stackId="1" stroke="var(--color-high)" fill="var(--color-high)" fillOpacity={0.3} />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Severity mix</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {(["critical", "high", "medium", "low", "info"] as const).map((k) => (
              <div key={k} className="flex items-center gap-3">
                <SeverityBadge severity={k} />
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-secondary">
                  <div
                    className="h-full bg-primary"
                    style={{ width: `${Math.max(4, (sev[k] / EVENTS.length) * 100)}%` }}
                  />
                </div>
                <span className="w-8 text-right font-mono text-xs tabular-nums text-muted-foreground">{sev[k]}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </section>

      <section>
        <div className="mb-3 flex items-end justify-between gap-3">
          <h2 className="text-sm font-medium">Captured attacks</h2>
          <Link to="/incidents" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
            All incidents <ArrowRight className="size-3.5" />
          </Link>
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          {ATTACKS.map((a) => (
            <Link
              key={a.id}
              to="/incidents/$id"
              params={{ id: a.id }}
              className="rounded-lg border border-border bg-card p-4 transition-colors hover:bg-accent/40"
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-[11px] text-subtle">{a.code}</span>
                <SeverityBadge severity={a.severity} />
                <Badge variant={a.status === "active" ? "critical" : a.status === "contained" ? "medium" : "ok"}>
                  {a.status}
                </Badge>
              </div>
              <h3 className="mt-2 text-base font-medium">{a.name}</h3>
              <p className="mt-1 text-sm text-muted-foreground">{a.headline}</p>
              <p className="mt-3 font-mono text-[11px] text-subtle">
                MTTD {a.mttd} · {a.sources.join(" · ")}
              </p>
            </Link>
          ))}
        </div>
      </section>

      <HuntPanel />

      <section className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Source health</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {(Object.keys(SOURCES) as Array<keyof typeof SOURCES>).map((k) => (
              <div key={k} className="flex items-start justify-between gap-3 border-b border-border pb-3 last:border-0 last:pb-0">
                <div>
                  <p className="text-sm">{SOURCES[k].label}</p>
                  <p className="text-xs text-muted-foreground">{SOURCES[k].product}</p>
                </div>
                <div className="text-right">
                  <Badge variant="ok">forwarding</Badge>
                  <p className="mt-1 font-mono text-[11px] tabular-nums text-muted-foreground">{src[k]} events</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>ATT&CK coverage in this window</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {techniques.map((id) => (
              <span key={id} className="rounded-sm border border-border px-2 py-1 font-mono text-[11px] text-muted-foreground">
                {id} {MITRE[id]?.name}
              </span>
            ))}
          </CardContent>
        </Card>
      </section>
    </div>
  );
}

function Kpi({ label, value, hint }: { label: string; value: string | number; hint: string }) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <p className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-1 font-mono text-2xl tabular-nums tracking-tight">{value}</p>
      <p className="text-xs text-subtle">{hint}</p>
    </div>
  );
}
