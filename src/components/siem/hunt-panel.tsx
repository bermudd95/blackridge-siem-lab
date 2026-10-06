import { useEffect, useRef } from "react";
import { toast } from "sonner";
import { Radio } from "lucide-react";
import { Button } from "@/components/ui/button";
import { EventRow } from "./event-row";
import { useHunt } from "@/lib/siem/store";
import { ATTACK_BY_ID, ATTACKS } from "@/lib/siem/attacks";
import { eventsForAttack } from "@/lib/siem/events";
import { EVENTS } from "@/lib/siem/events";

export function HuntPanel({ attackId }: { attackId?: string }) {
  const { playing, attackId: current, live, play, stop, tick, reset } = useHunt();
  const done = useRef(false);

  useEffect(() => {
    if (!playing) return;
    done.current = false;
    const id = window.setInterval(() => {
      const finished = tick();
      if (finished && !done.current) {
        done.current = true;
        const a = current ? ATTACK_BY_ID[current] : null;
        if (a) {
          toast("Incident captured", {
            description: `${a.code} ${a.name} is now in the notable index.`,
          });
        }
      }
    }, 280);
    return () => window.clearInterval(id);
  }, [playing, tick, current]);

  const streamId = attackId ?? current ?? ATTACKS[0].id;
  const total = eventsForAttack(streamId).length;
  const rows = playing || live.length ? live : EVENTS.slice(-8).reverse();

  return (
    <section className="rounded-lg border border-border bg-card">
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <div className="flex items-center gap-2">
          <span className={playing ? "live-dot size-2 rounded-full bg-critical" : "size-2 rounded-full bg-ok"} />
          <h2 className="text-sm font-medium">
            {playing ? "Live capture" : "Event stream"}
          </h2>
        </div>
        <p className="text-xs text-muted-foreground">
          {playing
            ? `Replaying ${ATTACK_BY_ID[streamId]?.name ?? streamId} · ${live.length}/${total}`
            : "Last indexed events. Replay an attack to watch the SIEM catch it."}
        </p>
        <div className="ml-auto flex flex-wrap gap-2">
          {playing ? (
            <Button variant="secondary" size="sm" onClick={stop}>
              Pause
            </Button>
          ) : (
            <Button
              size="sm"
              onClick={() => {
                reset();
                play(streamId);
              }}
            >
              <Radio className="size-3.5" />
              Replay {ATTACK_BY_ID[streamId]?.name ?? "attack"}
            </Button>
          )}
        </div>
      </div>
      <div className="max-h-[28rem] overflow-auto">
        {rows.length === 0 ? (
          <p className="px-4 py-8 text-sm text-muted-foreground">Waiting for events.</p>
        ) : (
          rows.map((e, i) => <EventRow key={`${e.id}-${i}`} event={e} flash={playing && i === 0} compact />)
        )}
      </div>
    </section>
  );
}
