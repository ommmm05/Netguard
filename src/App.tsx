import { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Overview from './pages/Overview';
import Visibility from './pages/Visibility';
import Detection from './pages/Detection';
import Alerts from './pages/Alerts';
import Forensics from './pages/Forensics';
import Assistant from './pages/Assistant';
import Codebase from './pages/Codebase';
import Settings from './pages/Settings';

type Page = 'overview' | 'visibility' | 'detection' | 'alerts' | 'forensics' | 'assistant' | 'codebase' | 'settings';

function LoadingScreen() {
  const [step, setStep] = useState(0);
  const steps = [
    'Initializing passive_sniffer.py...',
    'Loading ML models (XGBoost, RF, IsoForest)...',
    'Connecting to SQLite database...',
    'Starting SHAP explainer engine...',
    'Launching SOC Dashboard...',
  ];
  useEffect(() => {
    const intervals = steps.map((_, i) =>
      setTimeout(() => setStep(i + 1), (i + 1) * 450)
    );
    return () => intervals.forEach(clearTimeout);
  }, []);
  return (
    <div className="min-h-screen bg-[#0B1120] flex items-center justify-center">
      <div className="text-center max-w-sm w-full px-4">
        <div className="relative w-14 h-14 mx-auto mb-6">
          <div className="w-14 h-14 rounded-lg bg-[#111827] border border-[#243244] flex items-center justify-center">
            <svg className="w-7 h-7 text-[#06B6D4]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
        </div>
        <h1 className="text-xl font-bold text-white tracking-tight mb-1">NetGuard</h1>
        <p className="text-xs text-slate-400 mb-6">AI-Driven Network Visibility, Threat Detection & Forensics</p>
        <div className="w-full h-1 bg-[#1E293B] rounded-full mb-4 overflow-hidden">
          <div className="h-full bg-[#06B6D4] rounded-full transition-all duration-300"
            style={{ width: `${(step / steps.length) * 100}%` }} />
        </div>
        <div className="space-y-1.5 text-left bg-[#111827] border border-[#243244] p-3 rounded-lg">
          {steps.map((s, i) => (
            <div key={i} className={`flex items-center gap-2 text-xs transition-colors duration-200 ${i < step ? 'text-emerald-400' : i === step - 1 ? 'text-[#06B6D4]' : 'text-slate-600'}`}>
              <span className="font-mono">{i < step ? '✓' : i === step ? '►' : '·'}</span>
              <span className="font-mono text-[11px] truncate">{s}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [activePage, setActivePage] = useState<Page>('overview');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 2000);
    return () => clearTimeout(t);
  }, []);

  if (loading) return <LoadingScreen />;

  const renderPage = () => {
    switch (activePage) {
      case 'overview':    return <Overview onNavigate={(p) => setActivePage(p as Page)} />;
      case 'visibility':  return <Visibility />;
      case 'detection':   return <Detection />;
      case 'alerts':      return <Alerts onNavigate={(p) => setActivePage(p as Page)} />;
      case 'forensics':   return <Forensics />;
      case 'assistant':   return <Assistant />;
      case 'codebase':    return <Codebase />;
      case 'settings':    return <Settings />;
      default:            return <Overview onNavigate={(p) => setActivePage(p as Page)} />;
    }
  };

  return (
    <div className="flex h-screen bg-[#0B1120] text-slate-100 overflow-hidden font-sans">
      <Sidebar activePage={activePage} onNavigate={(p) => setActivePage(p as Page)} />

      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        <Topbar activePage={activePage} onNavigate={(p) => setActivePage(p as Page)} />
        <main className="flex-1 overflow-hidden relative bg-[#0B1120]">
          {renderPage()}
        </main>
      </div>
    </div>
  );
}
