/**
 * SecurityPostureChart
 * ====================
 * Donut chart: severity distribution across ALL findings.
 * Previously hardcoded — now driven by useDashboardStats() (real API).
 */

"use client";

import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import { useDashboardStats } from "@/hooks/use-dashboard-stats";

const SEV_COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High:     "#f97316",
  Medium:   "#eab308",
  Low:      "#3b82f6",
};

function ChartSkeleton() {
  return (
    <div className="animate-pulse rounded-2xl border border-slate-800 bg-slate-900/50 p-5">
      <div className="mb-6 space-y-2">
        <div className="h-4 w-36 rounded bg-slate-800" />
        <div className="h-3 w-48 rounded bg-slate-800" />
      </div>
      <div className="h-[320px] w-full rounded-xl bg-slate-900" />
    </div>
  );
}

export function SecurityPostureChart() {
  const {
    criticalFindings,
    highFindings,
    mediumFindings,
    lowFindings,
    totalFindings,
    isLoading,
  } = useDashboardStats();

  if (isLoading) return <ChartSkeleton />;

  const chartData = [
    { name: "Critical", value: criticalFindings, color: SEV_COLORS.Critical },
    { name: "High",     value: highFindings,     color: SEV_COLORS.High },
    { name: "Medium",   value: mediumFindings,   color: SEV_COLORS.Medium },
    { name: "Low",      value: lowFindings,      color: SEV_COLORS.Low },
  ].filter((d) => d.value > 0); // hide slices with 0 so the chart is clean

  const isEmpty = totalFindings === 0;

  return (
    <div className="rounded-2xl border border-slate-800 bg-[#111820]/90 p-5 shadow-xl shadow-black/10">
      <div className="mb-2 flex items-start justify-between">
        <div><p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-amber-300">Risk composition</p><h2 className="mt-1 text-lg font-semibold text-slate-100">Security posture</h2>
        <p className="mt-1 text-sm text-slate-500">Findings by severity across all scans</p></div>
        <span className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs text-slate-400">{totalFindings} total</span>
      </div>

      {isEmpty ? (
        <div className="flex h-[320px] items-center justify-center">
          <p className="text-sm text-slate-500">
            No findings yet. Run a scan to see your security posture.
          </p>
        </div>
      ) : (
        <>
          <div className="h-[280px] w-full min-w-0">
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={chartData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={70}
                  outerRadius={110}
                  paddingAngle={3}
                  label={({ name, percent }) =>
                    `${name} ${typeof percent === "number" ? `${(percent * 100).toFixed(0)}%` : ""}`
                  }
                  labelLine={false}
                >
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(value) => [value ?? 0, "Findings"]}
                  contentStyle={{
                    backgroundColor: "#111820",
                    border: "1px solid #334155",
                    borderRadius: "8px",
                    color: "#f4f4f5",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Legend with real counts */}
          <div className="mt-4 grid grid-cols-2 gap-3">
            {chartData.map((item) => (
              <div key={item.name} className="flex items-center gap-2">
                <div
                  className="h-3 w-3 shrink-0 rounded-full"
                  style={{ backgroundColor: item.color }}
                />
                <span className="text-sm text-zinc-300">{item.name}</span>
                <span className="ml-auto tabular-nums text-sm font-semibold text-zinc-100">
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
