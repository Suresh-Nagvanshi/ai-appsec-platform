import { Sidebar } from "./sidebar";
import { Navbar } from "./navbar";

export function DashboardShell({
  children,
}: {
  children: React.ReactNode;
}) {
  return (<div className="flex min-h-screen overflow-hidden bg-transparent"> <Sidebar />
    <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
      <Navbar />

      <main className="flex-1 overflow-auto px-4 pb-24 pt-5 sm:px-6 sm:pb-10 lg:px-8">
        {children}
      </main>
    </div>
  </div>
  );
}
