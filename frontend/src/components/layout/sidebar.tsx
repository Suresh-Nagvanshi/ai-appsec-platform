"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import {
  LayoutDashboard,
  AlertTriangle,
  ScanSearch,
  FolderGit2,
  FileText,
  Settings,
  Shield,
  Globe,
  CircleHelp,
  Activity,
} from "lucide-react";

const navigation = [
  {
    name: "Overview",
    href: "/",
    icon: LayoutDashboard,
  },
  {
    name: "Findings",
    href: "/findings",
    icon: AlertTriangle,
  },
  {
    name: "Scans",
    href: "/scans",
    icon: ScanSearch,
  },
  {
    name: "Repositories",
    href: "/repositories",
    icon: FolderGit2,
  },
  {
    name: "Website Security",
    href: "/website-security",
    icon: Globe,
  },
  {
    name: "Reports",
    href: "/reports",
    icon: FileText,
  },
  {
    name: "Settings",
    href: "/settings",
    icon: Settings,
  },
];

export function Sidebar() {
  const pathname = usePathname();
  const renderLinks = (mobile = false) => navigation.map((item) => {
        const Icon = item.icon;
        const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
        return (
          <Link key={item.name} href={item.href} className={`group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all ${active ? "bg-amber-400/12 text-amber-200 shadow-[inset_3px_0_0_#e4a956]" : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-100"} ${mobile ? "min-w-max" : ""}`}>
            <Icon className={`h-4 w-4 ${active ? "text-amber-300" : "text-slate-500 group-hover:text-slate-300"}`} />
            {item.name}
          </Link>
        );
      });

  return (<>
  <aside className="hidden w-[248px] shrink-0 flex-col border-r border-slate-800/80 bg-[#0b1016]/90 md:flex">
    <div className="flex h-[76px] items-center border-b border-slate-800/80 px-6">
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-amber-300 text-slate-950 shadow-lg shadow-amber-300/10"><Shield className="h-5 w-5" /></div>
        <div><span className="block text-sm font-semibold tracking-wide text-slate-100">AI AppSec</span><span className="mt-0.5 block text-[10px] uppercase tracking-[0.18em] text-slate-500">Security workspace</span></div>
      </div>
    </div>

    <nav className="flex-1 space-y-1 p-4">
      <p className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-600">Workspace</p>
      {renderLinks()}
    </nav>
    <div className="space-y-3 border-t border-slate-800/80 p-4">
      <div className="flex items-center gap-2 rounded-xl border border-emerald-500/15 bg-emerald-500/[0.06] px-3 py-2.5 text-xs text-emerald-300"><Activity className="h-3.5 w-3.5" />Analysis engine online</div>
      <Link href="/settings" className="flex items-center gap-3 px-3 text-xs text-slate-500 transition-colors hover:text-slate-200"><CircleHelp className="h-4 w-4" />Help and settings</Link>
    </div>
  </aside>
  <div className="fixed inset-x-0 bottom-0 z-40 overflow-x-auto border-t border-slate-800/90 bg-[#0b1016]/95 px-2 py-2 backdrop-blur-xl md:hidden"><nav className="flex min-w-max gap-1">{renderLinks(true)}</nav></div>
  </>);
}
