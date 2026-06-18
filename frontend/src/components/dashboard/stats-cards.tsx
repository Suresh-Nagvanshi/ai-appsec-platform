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
    <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6 animate-pulse">
      <div className="flex items-start justify-between">
        <div className="space-y-3">
          <div className="h-3 w-28 rounded bg-zinc-800" />
          <div className="h-8 w-16 rounded bg-zinc-800" />
        </div>
        <div className="rounded-lg bg-zinc-900 p-2">
          <div className="h-5 w-5 rounded bg-zinc-800" />
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
            className="rounded-xl border border-zinc-800 bg-zinc-950 p-6"
          >
            <div className="flex items-start justify-between">
              <div>
                <p className="text-sm text-zinc-400">{stat.title}</p>
                <h2
                  className={`mt-3 text-3xl font-bold tabular-nums ${
                    stat.highlight ? "text-red-400" : ""
                  }`}
                >
                  {stat.value}
                </h2>
              </div>
              <div className="rounded-lg bg-zinc-900 p-2">
                <Icon
                  className={`h-5 w-5 ${
                    stat.highlight ? "text-red-400" : "text-zinc-300"
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
