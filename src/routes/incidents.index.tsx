import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/siem/severity-badge";
import { ATTACKS } from "@/lib/siem/attacks";
import { eventsForAttack } from "@/lib/siem/events";
import { formatTs } from "@/lib/siem/query";

export const Route = createFileRoute("/incidents/")({ component: IncidentsPage });

function IncidentsPage() {
  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-6 md:px-8 md:py-8">
      <header>
        <h1 className="text-2xl font-medium tracking-tight">Incidents</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
          Four campaigns were captured during the lab window. Each notable is correlated across system logs, the
          honeypot, and the firewall.
        </p>
      </header>
      <ul className="space-y-3">
        {ATTACKS.map((a) => {
          const n = eventsForAttack(a.id).length;
          return (
            <li key={a.id}>
              <Link
                to="/incidents/$id"
                params={{ id: a.id }}
                className="flex flex-col gap-3 rounded-lg border border-border bg-card p-5 transition-colors hover:bg-accent/40 sm:flex-row sm:items-start sm:justify-between"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11px] text-subtle">{a.code}</span>
                    <SeverityBadge severity={a.severity} />
                    <Badge variant={a.status === "active" ? "critical" : a.status === "contained" ? "medium" : "ok"}>
                      {a.status}
                    </Badge>
                  </div>
                  <h2 className="mt-2 text-lg font-medium">{a.name}</h2>
                  <p className="mt-1 text-sm text-muted-foreground">{a.headline}</p>
                  <p className="mt-3 font-mono text-[11px] text-subtle">
                    {formatTs(a.started)} → {formatTs(a.ended)} UTC · {n} correlated events · MTTD {a.mttd}
                  </p>
                </div>
                <span className="inline-flex min-h-11 items-center gap-1 text-sm text-muted-foreground">
                  Investigate <ArrowRight className="size-4" />
                </span>
              </Link>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
