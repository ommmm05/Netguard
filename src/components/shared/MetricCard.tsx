import { LucideIcon } from 'lucide-react';
import { cn } from '../../utils/cn';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  iconColor?: string;
  trend?: string;
  trendUp?: boolean;
  alert?: boolean;
  className?: string;
  onClick?: () => void;
  glow?: 'red' | 'green' | 'blue' | 'yellow' | 'purple' | 'cyan';
}

export default function MetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  iconColor = 'text-cyan-400',
  trend,
  trendUp,
  alert,
  className,
  onClick,
}: MetricCardProps) {
  return (
    <div
      onClick={onClick}
      className={cn(
        'relative bg-[#111827] border border-[#243244] rounded-lg p-3.5',
        'transition-colors duration-150',
        onClick && 'cursor-pointer hover:border-[#334155] hover:bg-[#172033]',
        alert && 'border-[#EF4444]/50 bg-[#EF4444]/5',
        className
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <p className="text-[11px] font-medium text-[#94A3B8] tracking-wide mb-1 truncate uppercase">{title}</p>
          <p className={cn('text-xl font-bold font-mono tracking-tight', alert ? 'text-[#EF4444]' : 'text-[#E5E7EB]')}>
            {value}
          </p>
          {subtitle && <p className="text-[11px] text-[#94A3B8] mt-1 truncate">{subtitle}</p>}
          {trend && (
            <p className={cn('text-[11px] mt-1 font-medium', trendUp ? 'text-[#EF4444]' : 'text-[#22C55E]')}>
              {trendUp ? '↑' : '↓'} {trend}
            </p>
          )}
        </div>
        <div className={cn('p-2 rounded bg-[#172033] border border-[#243244] flex-shrink-0', alert && 'border-[#EF4444]/40 bg-[#EF4444]/10')}>
          <Icon className={cn('w-4 h-4', alert ? 'text-[#EF4444]' : iconColor)} />
        </div>
      </div>
    </div>
  );
}
