import { Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { JobProvider } from "@/hooks/JobProvider";
import DashboardPage from "@/pages/DashboardPage";
import DissectorPage from "@/pages/DissectorPage";
import ThreatsPage from "@/pages/ThreatsPage";
import TopologyPage from "@/pages/TopologyPage";
import StreamsPage from "@/pages/StreamsPage";
import CarvedFilesPage from "@/pages/CarvedFilesPage";
import EncyclopediaPage from "@/pages/EncyclopediaPage";
import TriagePage from "@/pages/TriagePage";
import ReportsPage from "@/pages/ReportsPage";

export default function App() {
  return (
    <JobProvider>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route path="dissector" element={<DissectorPage />} />
          <Route path="threats" element={<ThreatsPage />} />
          <Route path="topology" element={<TopologyPage />} />
          <Route path="streams" element={<StreamsPage />} />
          <Route path="carved" element={<CarvedFilesPage />} />
          <Route path="encyclopedia" element={<EncyclopediaPage />} />
          <Route path="triage" element={<TriagePage />} />
          <Route path="reports" element={<ReportsPage />} />
        </Route>
      </Routes>
    </JobProvider>
  );
}
