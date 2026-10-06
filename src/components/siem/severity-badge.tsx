import { Badge } from "@/components/ui/badge";
import type { Severity } from "@/lib/siem/types";

const map = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
} as const;

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge variant={map[severity]}>{severity}</Badge>;
}
