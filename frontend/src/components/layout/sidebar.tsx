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
  return (<aside className="hidden md:flex w-64 flex-col border-r border-zinc-800 bg-zinc-950"> <div className="flex h-16 items-center border-b border-zinc-800 px-6"> <div className="flex items-center gap-2"> <Shield className="h-6 w-6" />
    <span className="text-lg font-semibold">
      AI AppSec
    </span>
  </div>
  </div>

    <nav className="flex-1 p-4 space-y-2">
      {navigation.map((item) => {
        const Icon = item.icon;

        return (
          <Link
            key={item.name}
            href={item.href}
            className="
            flex items-center gap-3 rounded-lg
            px-3 py-2 text-sm font-medium
            transition-colors
            hover:bg-zinc-900
          "
          >
            <Icon className="h-4 w-4" />
            {item.name}
          </Link>
        );
      })}
    </nav>
  </aside>
  );
}
