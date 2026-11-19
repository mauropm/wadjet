import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from '@/components/app-shell';
import { WadjetEye } from '@/components/logo';
import { ToastProvider } from '@/components/ui/toast';
import { AuthProvider, useAuth } from '@/lib/auth';

import LoginPage from '@/pages/login';
import OverviewPage from '@/pages/overview';
import ProjectsPage from '@/pages/projects';
import ProjectDetailPage from '@/pages/project-detail';
import ProjectOverviewTab from '@/pages/project/tabs-overview';
import AssetsTab from '@/pages/project/tabs-assets';
import ProfilesTab from '@/pages/project/tabs-profiles';
import SessionsTab from '@/pages/project/tabs-sessions';
import FindingsTab from '@/pages/project/tabs-findings';
import ReportsTab from '@/pages/project/tabs-reports';
import SettingsTab from '@/pages/project/tabs-settings';
import NewScanWizard from '@/pages/new-scan';
import ScanDetailPage from '@/pages/scan-detail';
import AssetDetailPage from '@/pages/asset-detail';
import FindingDetailPage from '@/pages/finding-detail';
import ScannersPage from '@/pages/scanners';
import SettingsPage from '@/pages/settings';
import NotFoundPage from '@/pages/not-found';

function ProtectedShell() {
  const { user, booting } = useAuth();
  if (booting) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-base">
        <WadjetEye className="h-12 animate-pulse-dot text-accent" />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return <AppShell />;
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ToastProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route element={<ProtectedShell />}>
              <Route index element={<OverviewPage />} />
              <Route path="/projects" element={<ProjectsPage />} />
              <Route path="/projects/:id" element={<ProjectDetailPage />}>
                <Route index element={<ProjectOverviewTab />} />
                <Route path="assets" element={<AssetsTab />} />
                <Route path="profiles" element={<ProfilesTab />} />
                <Route path="scans" element={<SessionsTab />} />
                <Route path="findings" element={<FindingsTab />} />
                <Route path="reports" element={<ReportsTab />} />
                <Route path="settings" element={<SettingsTab />} />
              </Route>
              <Route path="/projects/:id/scans/new" element={<NewScanWizard />} />
              <Route path="/scans/:id" element={<ScanDetailPage />} />
              <Route path="/assets/:id" element={<AssetDetailPage />} />
              <Route path="/findings/:id" element={<FindingDetailPage />} />
              <Route path="/scanners" element={<ScannersPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
