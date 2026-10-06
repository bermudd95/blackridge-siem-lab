import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { ChevronDown } from "lucide-react";
import { SeverityBadge } from "./severity-badge";
import { formatTs } from "@/lib/siem/query";
import { INTEL } from "@/lib/siem/intel";
import type { SiemEvent } from "@/lib/siem/types";
import { cn } from "@/lib/utils";

export function EventRow({
  event,
  flash,
  compact,
}: {
  event: SiemEvent;
  flash?: boolean;
  compact?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const intel = (event.srcIp && INTEL[event.srcIp]) || (event.destIp && INTEL[event.destIp]);

  return (
    <article className={cn("border-b border-border last:border-0", flash && "row-enter bg-accent/40")}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-3 px-3 py-2.5 text-left hover:bg-accent/60 min-h-11"
      >
        <ChevronDown
          className={cn("mt-0.5 size-4 shrink-0 text-subtle transition-transform duration-150", open && "rotate-180")}
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <time className="font-mono text-[11px] tabular-nums text-muted-foreground">{formatTs(event.ts)}</time>
            <span className="font-mono text-[11px] uppercase tracking-wide text-subtle">{event.source}</span>
            <SeverityBadge severity={event.severity} />
            {event.incidentId ? (
              <Link
                to="/incidents/$id"
                params={{ id: event.incidentId }}
                className="font-mono text-[11px] text-primary hover:underline"
                onClick={(e) => e.stopPropagation()}
              >
                {event.incidentId}
              </Link>
            ) : null}
          </div>
          <p className={cn("mt-1 font-mono text-xs text-foreground/90", compact ? "truncate" : "line-clamp-2")}>
            {event.raw}
          </p>
        </div>
      </button>
      {open ? (
        <div className="grid gap-3 border-t border-border bg-background/40 px-4 py-3 sm:grid-cols-2">
          <dl className="grid grid-cols-[7.5rem_1fr] gap-y-1.5 text-xs">
            {[
              ["id", event.id],
              ["host", event.host],
              ["sourcetype", event.sourcetype],
              ["index", event.index],
              ["user", event.user],
              ["src", event.srcIp],
              ["dest", event.destIp],
              ["dport", event.destPort != null ? String(event.destPort) : undefined],
              ["process", event.process],
              ["action", event.action],
              ["eventcode", event.eventCode],
            ]
              .filter(([, v]) => v)
              .map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-subtle">{k}</dt>
                  <dd className="font-mono break-all">{v}</dd>
                </div>
              ))}
          </dl>
          <div className="space-y-2">
            {intel ? (
              <p className="text-xs text-muted-foreground">
                <span className="uppercase tracking-wide text-subtle">intel · {intel.verdict}</span>
                <br />
                {intel.org ? `${intel.org} · ` : ""}
                {intel.country ? `${intel.country} · ` : ""}
                {intel.note}
              </p>
            ) : null}
            {event.mitre?.length ? (
              <p className="font-mono text-[11px] text-muted-foreground">{event.mitre.join("  ")}</p>
            ) : null}
            <pre className="overflow-x-auto rounded-sm bg-secondary p-3 font-mono text-[11px] leading-relaxed text-foreground/80 whitespace-pre-wrap">
              {event.raw}
            </pre>
          </div>
        </div>
      ) : null}
    </article>
  );
}
