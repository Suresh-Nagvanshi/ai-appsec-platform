import { Sidebar } from "./sidebar";
import { Navbar } from "./navbar";

export function DashboardShell({
  children,
}: {
  children: React.ReactNode;
}) {
  return (<div className="flex h-screen overflow-hidden"> <Sidebar />
    <div className="flex flex-1 flex-col overflow-hidden">
      <Navbar />

      <main className="flex-1 overflow-auto p-6">
        {children}
      </main>
    </div>
  </div>
  );
}
