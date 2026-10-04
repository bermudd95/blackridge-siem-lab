import { createFileRoute, Link } from "@tanstack/react-router";
import { Printer } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/siem/severity-badge";
import { ATTACKS } from "@/lib/siem/attacks";
import { MITRE } from "@/lib/siem/intel";
import type { Recommendation } from "@/lib/siem/types";

export const Route = createFileRoute("/report")({ component: ReportPage });

const RECS: Recommendation[] = ATTACKS.flatMap((a) => a.recommendations);

function uniqueRecs(list: Recommendation[]) {
  const seen = new Set<string>();
  return list.filter((r) => {
    if (seen.has(r.title)) return false;
    seen.add(r.title);
    return true;
  });
}

function ReportPage() {
  const recs = uniqueRecs(RECS);
  const immediate = recs.filter((r) => r.horizon === "immediate");
  const d30 = recs.filter((r) => r.horizon === "30d");
  const d90 = recs.filter((r) => r.horizon === "90d");

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-8 px-4 py-8 md:px-0 md:py-12">
      <div className="no-print flex justify-end gap-2 px-4">
        <Button variant="secondary" onClick={() => window.print()}>
          <Printer className="size-4" /> Print / save PDF
        </Button>
      </div>

      <article className="print-document rounded-xl border border-border bg-card px-5 py-8 md:px-12 md:py-12">
        <p className="text-[11px] font-medium uppercase tracking-[0.22em] text-muted-foreground">
          TLP:AMBER · Board briefing · 2 October 2026
        </p>
        <h1 className="mt-3 text-3xl font-medium tracking-tight md:text-4xl">
          Post-incident assessment
        </h1>
        <p className="mt-3 text-base text-muted-foreground">
          Four confirmed intrusions against Meridian Capital on 1 October 2026. Prepared by Blackridge SOC from
          system logs, the DMZ honeypot, and edge firewall telemetry.
        </p>

        <section className="mt-8 rounded-md border border-critical/30 bg-critical/10 p-5">
          <p className="text-[11px] uppercase tracking-wide text-critical">Overall residual risk · Critical</p>
          <p className="mt-2 text-sm leading-relaxed">
            Ticket Forge produced a Domain Admin (svc_backup$) and a DCSync of NTDS. krbtgt has not been
            double-rotated. Treat the forest as untrusted until that completes. Ledgerlock encrypted the Q3 close
            share. Silent Siphon exfiltrated 42,118 employee records. Night Latch was contained on the honeypot
            but reused a live password pattern.
          </p>
        </section>

        <section className="mt-10">
          <h2 className="text-lg font-medium">What the board needs to know</h2>
          <ol className="mt-4 space-y-4 text-sm leading-relaxed text-muted-foreground">
            <li>
              <span className="text-foreground">This is a forest-level event, not four unrelated tickets.</span>{" "}
              Ledgerlock gave a foothold on FIN-WS-14; Ticket Forge used that same host to roast a service account
              and mint a Domain Admin. Containment of ransomware is not containment of identity.
            </li>
            <li>
              <span className="text-foreground">People data left the building.</span> Silent Siphon moved an HRIS
              payroll dump over DNS for six hours. This is a legal-clock event (state statutes; GDPR for EU
              contractors). Counsel should already be in the room.
            </li>
            <li>
              <span className="text-foreground">Detection worked where we had telemetry — and failed where we did not.</span>{" "}
              The honeypot and Sysmon caught Night Latch and Ledgerlock in minutes. There is no EDR. DNS had no
              volume baseline. RC4 Kerberos is still allowed. Those are design choices, not bad luck.
            </li>
            <li>
              <span className="text-foreground">Do not pay. Do rotate.</span> Ransom was not paid. The expensive
              action is identity: double-rotate krbtgt, reset every Domain Admin, kill all tickets, then restore
              finance from 30 September.
            </li>
          </ol>
        </section>

        <section className="mt-10">
          <h2 className="text-lg font-medium">Findings</h2>
          <div className="mt-4 space-y-8">
            {ATTACKS.map((a, i) => (
              <section key={a.id} className="border-t border-border pt-6">
                <p className="font-mono text-[11px] text-subtle">
                  Finding {i + 1} · {a.code}
                </p>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <h3 className="text-base font-medium">{a.name}</h3>
                  <SeverityBadge severity={a.severity} />
                </div>
                <p className="mt-2 text-sm text-foreground">{a.execFinding}</p>
                <p className="mt-2 text-sm text-muted-foreground">{a.businessImpact}</p>
                <p className="mt-3 font-mono text-[11px] text-subtle">
                  MTTD {a.mttd} · MTTR {a.mttr} · {a.mitre.map((t) => `${t} ${MITRE[t]?.name}`).join(" · ")}
                </p>
                <p className="mt-2">
                  <Link to="/incidents/$id" params={{ id: a.id }} className="text-xs text-primary hover:underline">
                    Evidence and timeline
                  </Link>
                </p>
              </section>
            ))}
          </div>
        </section>

        <section className="mt-10">
          <h2 className="text-lg font-medium">Business impact (range)</h2>
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-[11px] uppercase tracking-wide text-subtle">
                <tr>
                  <th className="pb-2 pr-4 font-medium">Item</th>
                  <th className="pb-2 font-medium">Estimate</th>
                </tr>
              </thead>
              <tbody className="text-muted-foreground">
                <tr className="border-t border-border">
                  <td className="py-2 pr-4">Q3 close delay / Ledgerlock restore</td>
                  <td className="py-2">$1.8–2.4M operational</td>
                </tr>
                <tr className="border-t border-border">
                  <td className="py-2 pr-4">HR PII notification, monitoring, regulatory</td>
                  <td className="py-2">$2–10M, excluding class action</td>
                </tr>
                <tr className="border-t border-border">
                  <td className="py-2 pr-4">Identity recovery (AD, VPN, DA, krbtgt)</td>
                  <td className="py-2">Staff time + residual golden-ticket risk until complete</td>
                </tr>
                <tr className="border-t border-border">
                  <td className="py-2 pr-4">Ransom paid</td>
                  <td className="py-2 text-foreground">$0</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <RecBlock title="Do this week" items={immediate} />
        <RecBlock title="30 days" items={d30} />
        <RecBlock title="90 days" items={d90} />

        <section className="mt-10 border-t border-border pt-6 text-sm leading-relaxed text-muted-foreground">
          <h2 className="text-lg font-medium text-foreground">Ask of the executive team</h2>
          <ol className="mt-3 list-decimal space-y-2 pl-5">
            <li>Authorize emergency identity recovery (krbtgt double-rotation, all DA resets) today.</li>
            <li>Stand up the breach-notification cell with Legal, HR, and Communications.</li>
            <li>Fund EDR coverage and a 24/7 honeypot/DNS alerting watch — the gap is staffing plus tooling.</li>
            <li>Accept that finance workstations must lose write access to the canonical close share before the next freeze.</li>
          </ol>
          <p className="mt-6 text-xs text-subtle">
            Blackridge SIEM Lab · synthetic telemetry for training · not a production investigation. Mapped to
            evidence in the winevent, honeypot, and network indexes for 1–2 October 2026.
          </p>
        </section>
      </article>
    </div>
  );
}

function RecBlock({ title, items }: { title: string; items: Recommendation[] }) {
  return (
    <section className="mt-10">
      <h2 className="text-lg font-medium">{title}</h2>
      <ul className="mt-4 space-y-4">
        {items.map((r) => (
          <li key={r.title} className="border-t border-border pt-4">
            <p className="text-sm font-medium">
              {r.title}{" "}
              <span className="font-normal text-subtle">· {r.owner}</span>
            </p>
            <p className="mt-1 text-sm text-muted-foreground">{r.detail}</p>
          </li>
        ))}
      </ul>
    </section>
  );
}
