// What the search window (Cmd+K) finds in Attack Simulation: hosts by name and tests by technique or name. Both are
// read whole from the API and filtered here, since each is a small, fixed list.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { Crosshair, Server } from "lucide-react";
import type { Host, PackTest } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [{ hosts }, { tests }] = await Promise.all([
      call<{ hosts: Host[] }>("/api/v1/hosts", { signal }),
      call<{ tests: PackTest[] }>("/api/v1/tests", { signal }),
    ]);
    const needle = q.toLowerCase();
    return [
      ...hosts
        .filter((h) => h.name.toLowerCase().includes(needle))
        .slice(0, 5)
        .map((h): SearchResult => ({
          id: `host:${h.id}`,
          label: h.name,
          detail: t(`hostStatuses.${h.status}`),
          kind: t("search.host"),
          icon: Server,
          href: "/hosts",
        })),
      ...tests
        .filter((x) => x.name.toLowerCase().includes(needle) || x.technique.toLowerCase().includes(needle) || x.techniqueName.toLowerCase().includes(needle))
        .slice(0, 6)
        .map((x): SearchResult => ({
          id: `test:${x.id}`,
          label: `${x.technique} ${x.name}`,
          detail: x.tactic,
          kind: t("search.test"),
          icon: Crosshair,
          href: "/tests",
        })),
    ];
  };
}
