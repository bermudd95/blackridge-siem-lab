import { create } from "zustand";
import type { SiemEvent } from "./types";
import { eventsForAttack } from "./events";

type HuntState = {
  playing: boolean;
  attackId: string | null;
  cursor: number;
  live: SiemEvent[];
  seen: string[];
  play: (attackId: string) => void;
  stop: () => void;
  tick: () => boolean;
  reset: () => void;
};

export const useHunt = create<HuntState>((set, get) => ({
  playing: false,
  attackId: null,
  cursor: 0,
  live: [],
  seen: [],
  play: (attackId) => {
    set({
      playing: true,
      attackId,
      cursor: 0,
      live: [],
      seen: get().seen.includes(attackId) ? get().seen : [...get().seen, attackId],
    });
  },
  stop: () => set({ playing: false }),
  tick: () => {
    const { attackId, cursor, playing } = get();
    if (!playing || !attackId) return false;
    const stream = eventsForAttack(attackId);
    if (cursor >= stream.length) {
      set({ playing: false });
      return false;
    }
    const next = stream[cursor];
    set((s) => ({ cursor: s.cursor + 1, live: [next, ...s.live].slice(0, 40) }));
    return cursor + 1 >= stream.length;
  },
  reset: () => set({ playing: false, attackId: null, cursor: 0, live: [] }),
}));
