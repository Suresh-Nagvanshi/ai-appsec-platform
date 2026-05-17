interface SeverityBadgeProps {
severity: string;
}

const severityStyles: Record<string, string> = {
CRITICAL:
"bg-red-500/15 text-red-400 border-red-500/30",

HIGH:
"bg-orange-500/15 text-orange-400 border-orange-500/30",

MEDIUM:
"bg-yellow-500/15 text-yellow-400 border-yellow-500/30",

LOW:
"bg-blue-500/15 text-blue-400 border-blue-500/30",

INFO:
"bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

export function SeverityBadge({
severity,
}: SeverityBadgeProps) {

const normalized =
severity?.toUpperCase() || "INFO";

return (
<span
className={`         inline-flex items-center rounded-full
        border px-2.5 py-1 text-xs font-medium
        ${severityStyles[normalized]}
      `}
>
{normalized} </span>
);
}
