import { useState } from 'react';
import {
  Shield, Eye, Cpu, AlertTriangle, Search,
  Settings, ChevronLeft, ChevronRight, Wifi, Radio,
  Database, FileText, MessageSquare, TrendingUp
} from 'lucide-react';
import { cn } from '../utils/cn';
interface NavItem {
  id: string;
  label: string;
  icon: typeof Shield;
  badge?: string | number;
  badgeColor?: string;
  divider?: boolean;
}

const navItems: NavItem[] = [
  { id: 'overview', label: 'SOC Overview', icon: TrendingUp },
  { id: 'visibility', label: 'Network Visibility', icon: Eye },
  { id: 'detection', label: 'AI Threat Detection', icon: Cpu },
  { id: 'alerts', label: 'Alert Center', icon: AlertTriangle, badgeColor: 'bg-red-500' },
  { id: 'forensics', label: 'Forensics & Intel', icon: Search },
  { id: 'assistant', label: 'AI Analyst Chat', icon: MessageSquare },
  { id: 'codebase', label: 'Project Codebase', icon: FileText, divider: true },
  { id: 'settings', label: 'Configuration', icon: Settings },
];

interface SidebarProps {
  activePage: string;
  onNavigate: (page: string) => void;
}

export default function Sidebar({ activePage, onNavigate }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className={cn(
      'flex flex-col bg-[#0B1120] border-r border-[#243244] transition-all duration-200 flex-shrink-0 relative z-20',
      collapsed ? 'w-16' : 'w-60'
    )}>
      {/* Logo */}
      <div className={cn('flex items-center border-b border-[#243244] flex-shrink-0 h-14', collapsed ? 'p-2 justify-center' : 'px-4 gap-3')}>
        <div className="flex-shrink-0">
          <div className="w-8 h-8 rounded bg-[#172033] border border-[#243244] flex items-center justify-center text-[#06B6D4]">
            <Shield className="w-4 h-4" />
          </div>
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <p className="text-[#E5E7EB] font-semibold text-sm tracking-tight">NetGuard</p>
            <p className="text-[#94A3B8] text-[11px] font-mono">SOC Enterprise</p>
          </div>
        )}
      </div>

      {/* Status Strip */}
      {!collapsed && (
        <div className="px-3.5 py-2 border-b border-[#243244] bg-[#0F172A]">
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span className="text-[#94A3B8]">ENGINE</span>
            <span className="text-[#22C55E] flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E]" />
              ONLINE
            </span>
          </div>
        </div>
      )}

      {/* Nav Items */}
      <nav className="flex-1 p-2 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activePage === item.id;
          return (
            <div key={item.id}>
              {item.divider && <div className="my-2 border-t border-[#243244]" />}
              <button
                onClick={() => onNavigate(item.id)}
                title={collapsed ? item.label : undefined}
                className={cn(
                  'w-full flex items-center rounded text-xs font-medium transition-colors duration-150',
                  collapsed ? 'p-2.5 justify-center' : 'px-3 py-2 gap-2.5',
                  isActive
                    ? 'bg-[#06B6D4]/10 text-[#06B6D4] font-semibold border-l-2 border-[#06B6D4] rounded-l-none'
                    : 'text-[#94A3B8] hover:text-[#E5E7EB] hover:bg-[#172033]'
                )}
              >
                <Icon className={cn('flex-shrink-0', collapsed ? 'w-4 h-4' : 'w-4 h-4', isActive ? 'text-[#06B6D4]' : 'text-[#94A3B8]')} />
                {!collapsed && (
                  <>
                    <span className="flex-1 text-left truncate">{item.label}</span>
                    {item.badge && (
                      <span className={cn('text-[10px] text-white rounded px-1.5 py-0.2 font-mono font-bold min-w-[18px] text-center', item.badgeColor || 'bg-[#243244]')}>
                        {item.badge}
                      </span>
                    )}
                  </>
                )}
                {collapsed && item.badge && (
                  <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-[#EF4444]" />
                )}
              </button>
            </div>
          );
        })}
      </nav>

      {/* Collapse Toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="absolute -right-3 top-16 w-5 h-5 bg-[#172033] border border-[#243244] rounded-full flex items-center justify-center text-[#94A3B8] hover:text-[#E5E7EB] hover:border-[#334155] transition-colors z-30"
      >
        {collapsed ? <ChevronRight className="w-3 h-3" /> : <ChevronLeft className="w-3 h-3" />}
      </button>
    </div>
  );
}
