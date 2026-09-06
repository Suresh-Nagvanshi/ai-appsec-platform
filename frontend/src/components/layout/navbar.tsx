"use client";

import { Bell, ChevronDown, ShieldCheck } from "lucide-react";
import { usePathname } from "next/navigation";

export function Navbar() {
  const pathname = usePathname();
  const section = pathname === "/" ? "Overview" : (pathname.split("/")[1]?.replaceAll("-", " ") || "Workspace").replace(/^./, (character) => character.toUpperCase());
  return <header className="flex min-h-[76px] items-center justify-between border-b border-slate-800/80 bg-[#0b1016]/75 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
    <div className="flex items-center gap-3"><div className="h-2 w-2 rounded-full bg-amber-300 shadow-[0_0_14px_rgba(228,169,86,0.8)]" /><div><p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">Security workspace</p><h1 className="mt-1 text-sm font-semibold capitalize tracking-wide text-slate-100">{section}</h1></div></div>
    <div className="flex items-center gap-3"><div className="hidden items-center gap-2 rounded-full border border-slate-800 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-400 sm:flex"><ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />Protected session</div><button aria-label="Notifications" className="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-800 text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-100"><Bell className="h-4 w-4" /></button><button className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/60 px-2.5 py-1.5 text-xs text-slate-300 hover:bg-slate-800"><span className="flex h-6 w-6 items-center justify-center rounded-lg bg-sky-400/15 font-semibold text-sky-300">A</span><span className="hidden sm:block">Analyst</span><ChevronDown className="hidden h-3.5 w-3.5 text-slate-500 sm:block" /></button></div>
  </header>;
}
