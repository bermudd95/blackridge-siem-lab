import { useEffect, useMemo, useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { Copy, Radio } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { HuntPanel } from "@/components/siem/hunt-panel";
import { EventRow } from "@/components/siem/event-row";
import { SeverityBadge } from "@/components/siem/severity-badge";
import { ATTACK_BY_ID } from "@/lib/siem/attacks";
import { eventsForAttack } from "@/lib/siem/events";
import { MITRE } from "@/lib/siem/intel";
import { formatTs } from "@/lib/siem/query";
import { useHunt } from "@/lib/siem/store";

export const Route = createFileRoute("/incidents/$id")({ component: IncidentDetail });

function notesKey(id: string) {
  return `blackridge.notes.${id}`;
}

function IncidentDetail() {
  const { id } = Route.useParams();
  const attack = ATTACK_BY_ID[id];
  const events = useMemo(() => (attack ? eventsForAttack(attack.id) : []), [attack]);
  const play = useHunt((s) => s.play);
  const reset = useHunt((s) => s.reset);
  const [notes, setNotes] = useState("");

  useEffect(() => {
    setNotes(window.localStorage.getItem(notesKey(id)) ?? "");
  }, [id]);

  if (!attack) {
    return (
      <div className="px-6 py-16 text-center">
        <p className="text-sm text-muted-foreground">No incident with that id.</p>
        <Link to="/incidents" className="mt-3 inline-block text-sm text-primary hover:underline">
          Back to incidents
        </Link>
      </div>
    );
  }

  function copyIocs() {
    const text = attack.iocs.map((i) => `${i.type}\t${i.value}\t${i.context}`).join("\n");
    void navigator.clipboard.writeText(text);
    toast("Indicators copied");
  }

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-6 md:px-8 md:py-8">
      <nav className="text-xs text-muted-foreground">
        <Link to="/incidents" className="hover:text-foreground">
          Incidents
        </Link>
        <span className="px-2">/</span>
        <span className="text-foreground">{attack.name}</span>
      </nav>

      <header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[11px] text-subtle">{attack.code}</span>
            <SeverityBadge severity={attack.severity} />
            <Badge variant={attack.status === "active" ? "critical" : attack.status === "contained" ? "medium" : "ok"}>
              {attack.status}
            </Badge>
          </div>
          <h1 className="mt-2 text-2xl font-medium tracking-tight md:text-3xl">{attack.name}</h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">{attack.headline}</p>
          <p className="mt-3 font-mono text-[11px] text-subtle">
            {formatTs(attack.started)} – {formatTs(attack.ended)} UTC · MTTD {attack.mttd} · MTTR {attack.mttr}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="secondary"
            onClick={() => {
              reset();
              play(attack.id);
              toast("Replay started", { description: "Watch the live stream catch this campaign." });
            }}
          >
            <Radio className="size-4" /> Replay capture
          </Button>
          <Button variant="outline" onClick={copyIocs}>
            <Copy className="size-4" /> Copy IOCs
          </Button>
          <Button asChild>
            <Link to="/report">Open briefing</Link>
          </Button>
        </div>
      </header>

      <section className="grid gap-3 sm:grid-cols-3">
        <Meta label="Assets" value={attack.assets.join(" · ")} />
        <Meta label="Sources" value={attack.sources.join(" · ")} />
        <Meta label="Correlated events" value={String(events.length)} />
      </section>

      <section className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
        <Card>
          <CardHeader>
            <CardTitle>What happened</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm leading-relaxed text-muted-foreground">
            {attack.story.map((p) => (
              <p key={p}>{p}</p>
            ))}
            <p className="text-foreground">{attack.businessImpact}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>ATT&CK</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {attack.mitre.map((tid) => (
              <div key={tid} className="flex items-baseline justify-between gap-3 border-b border-border py-2 last:border-0">
                <div>
                  <p className="font-mono text-xs">{tid}</p>
                  <p className="text-sm">{MITRE[tid]?.name}</p>
                </div>
                <p className="text-[11px] uppercase tracking-wide text-subtle">{MITRE[tid]?.tactic}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </section>

      <Card>
        <CardHeader>
          <CardTitle>Indicators</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-[11px] uppercase tracking-wide text-subtle">
              <tr>
                <th className="pb-2 pr-4 font-medium">Type</th>
                <th className="pb-2 pr-4 font-medium">Value</th>
                <th className="pb-2 font-medium">Context</th>
              </tr>
            </thead>
            <tbody>
              {attack.iocs.map((i) => (
                <tr key={i.value} className="border-t border-border">
                  <td className="py-2 pr-4 text-muted-foreground">{i.type}</td>
                  <td className="py-2 pr-4 font-mono text-xs break-all">{i.value}</td>
                  <td className="py-2 text-muted-foreground">{i.context}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <HuntPanel attackId={attack.id} />

      <section>
        <h2 className="mb-3 text-sm font-medium">Correlated timeline</h2>
        <div className="overflow-hidden rounded-lg border border-border bg-card">
          {events.map((e) => (
            <EventRow key={e.id} event={e} />
          ))}
        </div>
      </section>

      <Card>
        <CardHeader>
          <CardTitle>Analyst notes</CardTitle>
        </CardHeader>
        <CardContent>
          <textarea
            value={notes}
            onChange={(e) => {
              setNotes(e.target.value);
              window.localStorage.setItem(notesKey(id), e.target.value);
            }}
            className="min-h-32 w-full rounded-sm border border-input bg-background p-3 text-sm"
            placeholder="Local notes for this lab (stay on this browser)."
          />
        </CardContent>
      </Card>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <p className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-1 text-sm">{value}</p>
    </div>
  );
}
