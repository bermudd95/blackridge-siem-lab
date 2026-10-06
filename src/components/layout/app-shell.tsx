import { useEffect, useState, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { Activity, Database, FileText, Menu, Search, ShieldAlert, X } from "lucide-react";
import { Toaster } from "sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { EVENTS } from "@/lib/siem/events";
import { ATTACKS } from "@/lib/siem/attacks";

const NAV = [
  { to: "/", label: "Overview", icon: Activity },
  { to: "/search", label: "Search", icon: Search },
  { to: "/sources", label: "Sources", icon: Database },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
  { to: "/report", label: "Briefing", icon: FileText },
] as const;

function Clock() {
  const [now, setNow] = useState("2026-10-02 17:19:00");
  useEffect(() => {
    const tick = () => {
      const d = new Date();
      const pad = (n: number) => String(n).padStart(2, "0");
      setNow(
        `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`,
      );
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, []);
  return <span className="font-mono text-[11px] tabular-nums text-muted-foreground">{now} UTC</span>;
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [open, setOpen] = useState(false);
  const openIncidents = ATTACKS.filter((a) => a.status !== "eradicated").length;

  return (
    <TooltipProvider delayDuration={250}>
      <div className="flex min-h-dvh flex-col bg-background text-foreground">
        <p className="no-print bg-banner px-4 py-1.5 text-center text-[10px] font-medium uppercase tracking-[0.18em] text-muted-foreground">
          Training lab · synthetic telemetry · Meridian Capital
        </p>
        <header className="no-print sticky top-0 z-40 flex items-center gap-3 border-b border-border bg-background/95 px-3 py-2.5 backdrop-blur-sm md:px-4">
          <Button
            variant="ghost"
            size="icon"
            className="md:hidden"
            aria-label={open ? "Close menu" : "Open menu"}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? <X /> : <Menu />}
          </Button>
          <Link to="/" className="flex min-w-0 items-baseline gap-2">
            <span className="font-medium tracking-[0.16em] text-sm">BLACKRIDGE</span>
            <span className="hidden text-[11px] uppercase tracking-[0.18em] text-muted-foreground sm:inline">
              SIEM Lab
            </span>
          </Link>
          <div className="ml-auto flex items-center gap-3">
            <span className="hidden font-mono text-[11px] text-subtle sm:inline">
              {EVENTS.length} events · {ATTACKS.length} captured
            </span>
            <Clock />
          </div>
        </header>

        <div className="flex flex-1">
          <aside
            className={cn(
              "no-print z-30 border-border bg-card md:static md:flex md:w-52 md:shrink-0 md:flex-col md:border-r",
              open ? "fixed inset-x-0 top-[4.75rem] border-b p-2 md:top-auto" : "hidden md:flex",
            )}
          >
            <nav className="flex flex-col gap-0.5 p-2">
              {NAV.map((item) => {
                const active = item.to === "/" ? pathname === "/" : pathname.startsWith(item.to);
                const Icon = item.icon;
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    onClick={() => setOpen(false)}
                    className={cn(
                      "flex min-h-11 items-center gap-2.5 rounded-sm px-3 text-sm transition-colors",
                      active ? "bg-accent text-foreground" : "text-muted-foreground hover:bg-accent/70 hover:text-foreground",
                    )}
                  >
                    <Icon className="size-4 shrink-0" />
                    <span>{item.label}</span>
                    {item.to === "/incidents" ? (
                      <span className="ml-auto font-mono text-[11px] tabular-nums text-critical">{openIncidents}</span>
                    ) : null}
                  </Link>
                );
              })}
            </nav>
            <p className="mt-auto hidden px-4 pb-4 text-[11px] leading-relaxed text-subtle md:block">
              Indexes winevent, honeypot, network. Collection window 01–02 Oct 2026.
            </p>
          </aside>
          <main className="min-w-0 flex-1">{children}</main>
        </div>
        <Toaster theme="dark" position="bottom-right" richColors={false} />
      </div>
    </TooltipProvider>
  );
}
