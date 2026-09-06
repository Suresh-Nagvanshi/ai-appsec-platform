import { StatsCards } from "@/components/dashboard/stats-cards";
import { SecurityPostureChart } from "@/components/dashboard/security-posture-chart";
import {
  RecentFindings,
  RecentScans,
} from "@/components/dashboard/recent-findings";
import Link from "next/link";
import { ArrowUpRight, ScanSearch } from "lucide-react";

export default function DashboardPage() {
  return (
    <div className="mx-auto w-full max-w-[1500px] space-y-7">
      <div className="flex flex-col justify-between gap-5 border-b border-slate-800/80 pb-6 lg:flex-row lg:items-end">
        <div><p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.22em] text-amber-300">Command center / September 2026</p><h1 className="text-3xl font-semibold tracking-[-0.03em] text-slate-50 sm:text-4xl">Know what is exposed.</h1><p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">A live view of code risk, attack surface, and remediation progress across your security workspace.</p></div>
        <div className="flex flex-wrap gap-2"><Link href="/scans" className="inline-flex h-10 items-center gap-2 rounded-xl bg-amber-300 px-4 text-sm font-semibold text-slate-950 shadow-lg shadow-amber-300/10 transition hover:bg-amber-200"><ScanSearch className="h-4 w-4" />Start a scan<ArrowUpRight className="h-3.5 w-3.5" /></Link><Link href="/reports" className="inline-flex h-10 items-center rounded-xl border border-slate-700 bg-slate-900/60 px-4 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:bg-slate-800">View reports</Link></div>
      </div>

      {/* Row 1: KPI cards */}
      <StatsCards />

      {/* Row 2: Chart + Recent Findings */}
      <div className="grid gap-5 xl:grid-cols-[1.1fr_0.9fr]">
        <SecurityPostureChart />
        <RecentFindings />
      </div>

      {/* Row 3: Recent Scans (full width) */}
      <RecentScans />
    </div>
  );
}
