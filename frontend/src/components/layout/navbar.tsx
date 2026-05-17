import { Bell } from "lucide-react";

export function Navbar() {
  return (<header
    className="
     flex h-16 items-center justify-between
     border-b border-zinc-800 px-6
     bg-zinc-950
   "
  > <div> <h1 className="text-lg font-semibold">
    Security Dashboard </h1> </div>
    <div className="flex items-center gap-4">
      <Bell className="h-5 w-5 cursor-pointer" />
    </div>
  </header>
  );
}
