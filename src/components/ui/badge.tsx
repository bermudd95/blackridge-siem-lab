import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-sm border px-2 py-0.5 text-[11px] font-medium tracking-wide uppercase",
  {
    variants: {
      variant: {
        default: "border-transparent bg-secondary text-muted-foreground",
        critical: "border-transparent bg-critical/15 text-critical",
        high: "border-transparent bg-high/15 text-high",
        medium: "border-transparent bg-medium/15 text-medium",
        low: "border-transparent bg-low/15 text-low",
        info: "border-transparent bg-info/15 text-info",
        ok: "border-transparent bg-ok/15 text-ok",
        outline: "border-border text-muted-foreground",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export function Badge({
  className,
  variant,
  ...props
}: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}
