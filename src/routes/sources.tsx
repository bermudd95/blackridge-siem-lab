import { createFileRoute } from "@tanstack/react-router";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { EventRow } from "@/components/siem/event-row";
import { EVENTS, sourceStats } from "@/lib/siem/events";
import { SOURCES } from "@/lib/siem/intel";
import type { SourceKind } from "@/lib/siem/types";

export const Route = createFileRoute("/sources")({ component: SourcesPage });

const ORDER: SourceKind[] = ["system", "honeypot", "firewall"];

function SourcesPage() {
  const stats = sourceStats();

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-6 md:px-8 md:py-8">
      <header>
        <h1 className="text-2xl font-medium tracking-tight">Data sources</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
          Three collectors feed the lab index. The topology below is the Meridian estate as the SIEM sees it.
        </p>
      </header>

      <Topology />

      <div className="grid gap-3 md:grid-cols-3">
        {ORDER.map((k) => (
          <Card key={k}>
            <CardHeader>
              <div className="flex items-center justify-between gap-2">
                <CardTitle>{SOURCES[k].label}</CardTitle>
                <Badge variant="ok">live</Badge>
              </div>
              <CardDescription>{SOURCES[k].product}</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">{SOURCES[k].description}</p>
              <dl className="mt-4 grid grid-cols-[5.5rem_1fr] gap-y-1 font-mono text-[11px]">
                <dt className="text-subtle">host</dt>
                <dd>{SOURCES[k].host}</dd>
                <dt className="text-subtle">index</dt>
                <dd>{SOURCES[k].index}</dd>
                <dt className="text-subtle">sourcetype</dt>
                <dd>{SOURCES[k].dest}</dd>
                <dt className="text-subtle">events</dt>
                <dd className="tabular-nums">{stats[k]}</dd>
              </dl>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs defaultValue="system">
        <TabsList className="w-full justify-start overflow-x-auto">
          {ORDER.map((k) => (
            <TabsTrigger key={k} value={k}>
              {SOURCES[k].label}
            </TabsTrigger>
          ))}
        </TabsList>
        {ORDER.map((k) => (
          <TabsContent key={k} value={k}>
            <div className="overflow-hidden rounded-lg border border-border bg-card">
              {EVENTS.filter((e) => e.source === k)
                .slice(-12)
                .reverse()
                .map((e) => (
                  <EventRow key={e.id} event={e} compact />
                ))}
            </div>
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}

function Topology() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Network as indexed</CardTitle>
        <CardDescription>Internet → edge firewall → DMZ honeypot · users · servers. SIEM collectors on each plane.</CardDescription>
      </CardHeader>
      <CardContent className="overflow-x-auto">
        <svg
          viewBox="0 0 760 220"
          className="h-auto w-full min-w-[36rem] text-muted-foreground"
          role="img"
          aria-label="Network topology: internet, firewall, honeypot, users, domain controller"
        >
          <rect x="8" y="70" width="120" height="80" rx="8" fill="var(--color-secondary)" stroke="var(--color-border)" />
          <text x="68" y="106" textAnchor="middle" fill="var(--color-foreground)" fontSize="12">
            Internet
          </text>
          <text x="68" y="124" textAnchor="middle" fill="currentColor" fontSize="10">
            TOR · C2 · VPN
          </text>

          <line x1="128" y1="110" x2="168" y2="110" stroke="var(--color-primary)" strokeWidth="1.5" />

          <rect x="168" y="62" width="150" height="96" rx="8" fill="var(--color-secondary)" stroke="var(--color-primary)" />
          <text x="243" y="96" textAnchor="middle" fill="var(--color-foreground)" fontSize="12">
            FW-EDGE-01
          </text>
          <text x="243" y="114" textAnchor="middle" fill="currentColor" fontSize="10">
            Palo Alto PA-3220
          </text>
          <text x="243" y="132" textAnchor="middle" fill="currentColor" fontSize="10">
            index=network
          </text>

          <line x1="318" y1="90" x2="368" y2="48" stroke="var(--color-border)" />
          <line x1="318" y1="110" x2="368" y2="110" stroke="var(--color-border)" />
          <line x1="318" y1="130" x2="368" y2="172" stroke="var(--color-border)" />

          <rect x="368" y="16" width="160" height="64" rx="8" fill="var(--color-secondary)" stroke="var(--color-border)" />
          <text x="448" y="42" textAnchor="middle" fill="var(--color-foreground)" fontSize="12">
            HPOT-SSH-01
          </text>
          <text x="448" y="60" textAnchor="middle" fill="currentColor" fontSize="10">
            Cowrie · 10.50.1.20
          </text>

          <rect x="368" y="78" width="160" height="64" rx="8" fill="var(--color-secondary)" stroke="var(--color-border)" />
          <text x="448" y="104" textAnchor="middle" fill="var(--color-foreground)" fontSize="12">
            User VLANs
          </text>
          <text x="448" y="122" textAnchor="middle" fill="currentColor" fontSize="10">
            FIN-WS-14 · HR-LAP-07
          </text>

          <rect x="368" y="140" width="160" height="64" rx="8" fill="var(--color-secondary)" stroke="var(--color-border)" />
          <text x="448" y="166" textAnchor="middle" fill="var(--color-foreground)" fontSize="12">
            MERIDIAN-DC01
          </text>
          <text x="448" y="184" textAnchor="middle" fill="currentColor" fontSize="10">
            FIN-FS-01 · winevent
          </text>

          <rect x="568" y="62" width="180" height="96" rx="8" fill="var(--color-card)" stroke="var(--color-primary)" />
          <text x="658" y="100" textAnchor="middle" fill="var(--color-foreground)" fontSize="12">
            Blackridge SIEM
          </text>
          <text x="658" y="118" textAnchor="middle" fill="currentColor" fontSize="10">
            3 indexes · 4 notables
          </text>
          <text x="658" y="136" textAnchor="middle" fill="currentColor" fontSize="10">
            Splunk-class search
          </text>

          <line x1="528" y1="48" x2="568" y2="90" stroke="var(--color-primary)" strokeDasharray="3 3" />
          <line x1="528" y1="110" x2="568" y2="110" stroke="var(--color-primary)" strokeDasharray="3 3" />
          <line x1="528" y1="172" x2="568" y2="130" stroke="var(--color-primary)" strokeDasharray="3 3" />
        </svg>
      </CardContent>
    </Card>
  );
}
