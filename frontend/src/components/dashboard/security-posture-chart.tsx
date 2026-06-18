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
  Legend,
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
    <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6 animate-pulse">
      <div className="mb-6 space-y-2">
        <div className="h-4 w-36 rounded bg-zinc-800" />
        <div className="h-3 w-48 rounded bg-zinc-800" />
      </div>
      <div className="h-[320px] w-full rounded-lg bg-zinc-900" />
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
    <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
      <div className="mb-6">
        <h2 className="text-lg font-semibold">Security Posture</h2>
        <p className="text-sm text-zinc-400">Findings severity distribution</p>
      </div>

      {isEmpty ? (
        <div className="flex h-[320px] items-center justify-center">
          <p className="text-sm text-zinc-500">
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
                    `${name} ${(percent * 100).toFixed(0)}%`
                  }
                  labelLine={false}
                >
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(value: number) => [value, "Findings"]}
                  contentStyle={{
                    backgroundColor: "#18181b",
                    border: "1px solid #3f3f46",
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
