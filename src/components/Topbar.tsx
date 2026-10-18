import { Bell, Search, RefreshCw, Clock, Wifi } from 'lucide-react';

interface TopbarProps {
  activePage: string;
  onNavigate: (page: string) => void;
}

const pageLabels: Record<string, { title: string; sub: string }> = {
  overview: { title: 'SOC Overview', sub: 'Real-time threat intelligence dashboard' },
  visibility: { title: 'Network Visibility', sub: 'Passive traffic analysis & host discovery' },
  detection: { title: 'AI Threat Detection', sub: 'ML-powered intrusion detection system' },
  alerts: { title: 'Alert Center', sub: 'Prioritized security event management' },
  forensics: { title: 'Forensics & Intel', sub: 'SHAP explainability & incident intelligence' },
  assistant: { title: 'AI Analyst Chat', sub: 'Interactive threat investigation assistant' },
  codebase: { title: 'Project Codebase', sub: 'Implementation-ready source code scaffold' },
  settings: { title: 'Platform Configuration', sub: 'System settings & integrations' },
};

export default function Topbar({ activePage, onNavigate }: TopbarProps) {
  const page = pageLabels[activePage] || pageLabels.overview;

  return (
    <header className="h-14 bg-[#0F172A] border-b border-[#243244] flex items-center px-4 gap-3 flex-shrink-0 z-10">
      {/* Page title */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <h1 className="text-[#E5E7EB] font-semibold text-sm truncate">{page.title}</h1>
          <span className="text-[#334155] hidden sm:inline">·</span>
          <span className="text-[#94A3B8] text-xs hidden sm:inline truncate">{page.sub}</span>
        </div>
      </div>

      {/* Live feed indicator */}
      <div className="hidden md:flex items-center gap-2 bg-[#111827] border border-[#243244] rounded px-2.5 py-1">
        <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E]" />
        <span className="text-[11px] text-[#22C55E] font-mono font-medium tracking-wide">LIVE TELEMETRY</span>
      </div>

      {/* Build info */}
      <div className="hidden lg:flex items-center gap-1.5 text-xs text-[#94A3B8] font-mono">
        <Clock className="w-3.5 h-3.5 text-[#64748B]" />
        <span>Connected</span>
      </div>

      {/* Alerts bell */}
      <button
        onClick={() => onNavigate('alerts')}
        className="relative p-2 text-[#94A3B8] hover:text-[#E5E7EB] hover:bg-[#172033] rounded transition-colors"
        title="View Alerts"
      >
        <Bell className="w-4 h-4" />
        <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-[#EF4444]" />
      </button>

      {/* SOC Analyst pill */}
      <div className="hidden sm:flex items-center gap-2 pl-3 border-l border-[#243244]">
        <div className="w-7 h-7 rounded bg-[#172033] border border-[#243244] flex items-center justify-center text-xs font-mono font-bold text-[#06B6D4]">
          SOC
        </div>
        <div className="hidden xl:block">
          <p className="text-xs text-[#E5E7EB] font-medium leading-none">Security Analyst</p>
          <p className="text-[10px] text-[#94A3B8] font-mono leading-none mt-1">Tier-2 Active</p>
        </div>
      </div>
    </header>
  );
}
