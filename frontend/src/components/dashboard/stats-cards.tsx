/**
 * StatsCards
 * ==========
 * KPI cards: Total Findings | Critical | Repositories | Resolved
 * Previously hardcoded — now driven by useDashboardStats() (real API).
 */

"use client";

import {
  AlertTriangle,
  ShieldAlert,
  FolderGit2,
  CheckCircle2,
} from "lucide-react";
import { useDashboardStats } from "@/hooks/use-dashboard-stats";

// Skeleton for a single card while loading
function CardSkeleton() {
  return (
    <div className="animate-pulse rounded-2xl border border-slate-800 bg-slate-900/50 p-5">
      <div className="flex items-start justify-between">
        <div className="space-y-3">
          <div className="h-3 w-28 rounded bg-slate-800" />
          <div className="h-8 w-16 rounded bg-slate-800" />
        </div>
        <div className="rounded-xl bg-slate-800 p-2">
          <div className="h-5 w-5 rounded bg-slate-700" />
        </div>
      </div>
    </div>
  );
}

export function StatsCards() {
  const {
    totalFindings,
    criticalFindings,
    repositoryCount,
    resolvedFindings,
    isLoading,
  } = useDashboardStats();

  if (isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {[0, 1, 2, 3].map((i) => <CardSkeleton key={i} />)}
      </div>
    );
  }

  const stats = [
    {
      title: "Total Findings",
      value: totalFindings,
      icon: AlertTriangle,
    },
    {
      title: "Critical Findings",
      value: criticalFindings,
      icon: ShieldAlert,
      highlight: criticalFindings > 0,
    },
    {
      title: "Repositories Scanned",
      value: repositoryCount,
      icon: FolderGit2,
    },
    {
      title: "Resolved Findings",
      value: resolvedFindings,
      icon: CheckCircle2,
    },
  ];

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {stats.map((stat) => {
        const Icon = stat.icon;
        return (
          <div
            key={stat.title}
            className={`relative overflow-hidden rounded-2xl border border-slate-800 bg-[#111820]/90 p-5 shadow-xl shadow-black/10 ${stat.highlight ? "border-red-500/30" : ""}`}
          >
            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs font-medium uppercase tracking-[0.14em] text-slate-500">{stat.title}</p>
                <h2
                  className={`mt-3 text-3xl font-bold tabular-nums ${
                    stat.highlight ? "text-red-300" : "text-slate-100"
                  }`}
                >
                  {stat.value}
                </h2>
              </div>
              <div className={`rounded-xl p-2.5 ${stat.highlight ? "bg-red-400/10" : "bg-slate-800/80"}`}>
                <Icon
                  className={`h-5 w-5 ${
                    stat.highlight ? "text-red-300" : "text-amber-200"
                  }`}
                />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
