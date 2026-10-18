const colorMap: Record<string, { badge: string; dot: string }> = {
  critical: { badge: 'bg-[#DC2626]/10 text-[#DC2626] border border-[#DC2626]/30', dot: 'bg-[#DC2626]' },
  high: { badge: 'bg-[#EF4444]/10 text-[#EF4444] border border-[#EF4444]/30', dot: 'bg-[#EF4444]' },
  medium: { badge: 'bg-[#F59E0B]/10 text-[#F59E0B] border border-[#F59E0B]/30', dot: 'bg-[#F59E0B]' },
  low: { badge: 'bg-[#06B6D4]/10 text-[#06B6D4] border border-[#06B6D4]/30', dot: 'bg-[#06B6D4]' },
  info: { badge: 'bg-[#334155]/20 text-[#94A3B8] border border-[#334155]/40', dot: 'bg-[#94A3B8]' },
  active: { badge: 'bg-[#22C55E]/10 text-[#22C55E] border border-[#22C55E]/30', dot: 'bg-[#22C55E]' },
  running: { badge: 'bg-[#22C55E]/10 text-[#22C55E] border border-[#22C55E]/30', dot: 'bg-[#22C55E]' },
  stopped: { badge: 'bg-[#334155]/20 text-[#94A3B8] border border-[#334155]/40', dot: 'bg-[#64748B]' },
  suspicious: { badge: 'bg-[#F59E0B]/10 text-[#F59E0B] border border-[#F59E0B]/30', dot: 'bg-[#F59E0B]' },
  malicious: { badge: 'bg-[#EF4444]/10 text-[#EF4444] border border-[#EF4444]/30', dot: 'bg-[#EF4444]' },
  open: { badge: 'bg-[#EF4444]/10 text-[#EF4444] border border-[#EF4444]/30', dot: 'bg-[#EF4444]' },
  closed: { badge: 'bg-[#334155]/20 text-[#94A3B8] border border-[#334155]/40', dot: 'bg-[#64748B]' },
  investigating: { badge: 'bg-[#F59E0B]/10 text-[#F59E0B] border border-[#F59E0B]/30', dot: 'bg-[#F59E0B]' },
  escalated: { badge: 'bg-[#A855F7]/10 text-[#A855F7] border border-[#A855F7]/30', dot: 'bg-[#A855F7]' },
  stable: { badge: 'bg-[#22C55E]/10 text-[#22C55E] border border-[#22C55E]/30', dot: 'bg-[#22C55E]' },
  completed: { badge: 'bg-[#22C55E]/10 text-[#22C55E] border border-[#22C55E]/30', dot: 'bg-[#22C55E]' },
  error: { badge: 'bg-[#EF4444]/10 text-[#EF4444] border border-[#EF4444]/30', dot: 'bg-[#EF4444]' },
};

const sizeMap = {
  xs: 'text-[10px] px-1.5 py-0.5',
  sm: 'text-xs px-2 py-0.5',
  md: 'text-xs px-2.5 py-1',
};

interface StatusBadgeProps {
  status: string;
  size?: 'xs' | 'sm' | 'md';
  pulse?: boolean;
}

export default function StatusBadge({ status, size = 'sm' }: StatusBadgeProps) {
  const key = (status || '').toLowerCase();
  const cfg = colorMap[key] || {
    badge: 'bg-[#334155]/20 text-[#94A3B8] border border-[#334155]/40',
    dot: 'bg-[#94A3B8]',
  };
  const sizeClass = sizeMap[size];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded font-medium font-mono uppercase tracking-wider ${cfg.badge} ${sizeClass}`}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${cfg.dot}`} />
      {status}
    </span>
  );
}
