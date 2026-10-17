import { createContext, useContext, useState } from "react";

interface JobCtx {
  jobId: string | null;
  setJobId: (id: string | null) => void;
}

const Ctx = createContext<JobCtx>({ jobId: null, setJobId: () => {} });

export function JobProvider({ children }: { children: React.ReactNode }) {
  const [jobId, setJobId] = useState<string | null>(null);
  return <Ctx.Provider value={{ jobId, setJobId }}>{children}</Ctx.Provider>;
}

export const useJob = () => useContext(Ctx);
