import { useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Search as SearchIcon } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { EventRow } from "@/components/siem/event-row";
import { EVENTS } from "@/lib/siem/events";
import { SAVED_SEARCHES, fieldTop, searchEvents } from "@/lib/siem/query";

export const Route = createFileRoute("/search")({ component: SearchPage });

function SearchPage() {
  const [draft, setDraft] = useState("index=*");
  const [query, setQuery] = useState("index=*");
  const results = useMemo(() => searchEvents(EVENTS, query), [query]);
  const tops = {
    source: fieldTop(results, "source"),
    host: fieldTop(results, "host"),
    severity: fieldTop(results, "severity"),
    user: fieldTop(results, "user"),
  };

  function run(q: string) {
    setDraft(q);
    setQuery(q);
  }

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-4 px-4 py-6 md:px-8 md:py-8">
      <header>
        <h1 className="text-2xl font-medium tracking-tight">Search</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          SPL-style filters: <span className="font-mono text-foreground/80">field=value</span>, quoted phrases,{" "}
          <span className="font-mono text-foreground/80">-exclude</span>. Indexes winevent, honeypot, network.
        </p>
      </header>

      <form
        className="flex flex-col gap-2 sm:flex-row"
        onSubmit={(e) => {
          e.preventDefault();
          setQuery(draft);
        }}
      >
        <div className="relative flex-1">
          <SearchIcon className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-subtle" />
          <Input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            aria-label="Search query"
            className="pl-10"
            placeholder='source=firewall dest_port=22  OR  powershell'
          />
        </div>
        <Button type="submit" className="sm:w-28">
          Run
        </Button>
      </form>

      <div className="flex flex-wrap gap-2">
        {SAVED_SEARCHES.map((s) => (
          <button
            key={s.query}
            type="button"
            onClick={() => run(s.query)}
            className="min-h-11 rounded-sm border border-border px-3 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            {s.label}
          </button>
        ))}
      </div>

      <p className="font-mono text-xs text-muted-foreground">
        {results.length} events · query <span className="text-foreground">{query}</span>
      </p>

      <div className="grid gap-4 lg:grid-cols-[16rem_1fr]">
        <aside className="h-fit rounded-lg border border-border bg-card p-4">
          <p className="text-[11px] uppercase tracking-wide text-muted-foreground">Selected fields</p>
          {(
            [
              ["source", tops.source],
              ["host", tops.host],
              ["severity", tops.severity],
              ["user", tops.user],
            ] as const
          ).map(([name, rows]) => (
            <div key={name} className="mt-3">
              <p className="font-mono text-[11px] text-subtle">{name}</p>
              <ul className="mt-1 space-y-1">
                {rows.map((r) => (
                  <li key={r.value}>
                    <button
                      type="button"
                      className="flex w-full min-h-9 items-center justify-between gap-2 rounded-sm px-1 text-left text-xs hover:bg-accent"
                      onClick={() => run(`${query} ${name}=${r.value}`.replace("index=* ", ""))}
                    >
                      <span className="truncate font-mono">{r.value}</span>
                      <span className="tabular-nums text-muted-foreground">{r.count}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </aside>
        <div className="overflow-hidden rounded-lg border border-border bg-card">
          {results.length === 0 ? (
            <p className="px-4 py-10 text-sm text-muted-foreground">No events match this query.</p>
          ) : (
            results.map((e) => <EventRow key={e.id} event={e} />)
          )}
        </div>
      </div>
    </div>
  );
}
