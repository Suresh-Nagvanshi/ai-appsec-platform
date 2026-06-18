import { StatsCards } from "@/components/dashboard/stats-cards";
import { SecurityPostureChart } from "@/components/dashboard/security-posture-chart";
import {
  RecentFindings,
  RecentScans,
} from "@/components/dashboard/recent-findings";

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Overview</h1>
        <p className="mt-2 text-zinc-400">
          Security posture overview and recent activity.
        </p>
      </div>

      {/* Row 1: KPI cards */}
      <StatsCards />

      {/* Row 2: Chart + Recent Findings */}
      <div className="grid gap-6 xl:grid-cols-2">
        <SecurityPostureChart />
        <RecentFindings />
      </div>

      {/* Row 3: Recent Scans (full width) */}
      <RecentScans />
    </div>
  );
}
