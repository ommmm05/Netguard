import { useEffect, useState } from 'react';
import { AlertTriangle, Filter, Download, ChevronDown, ChevronUp, Shield, Clock, Cpu } from 'lucide-react';

import { API_BASE, apiFetch } from '../api/config';
import StatusBadge from '../components/shared/StatusBadge';

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

type UiAlert = {
  id: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  srcIp: string;
  dstIp: string;
  protocol: string;
  attackType: string;
  confidence: number;
  model: string;
  status: 'open' | 'investigating' | 'escalated' | 'closed';
  features?: Record<string, unknown>;
  mitre?: string;
  mitrePhase?: string;
  topShapFeatures?: any[];
  remediation?: string[];
  flowId?: string | null;
};

function normalizeFromApi(a: Record<string, unknown>): UiAlert {
  const f = (a.features as Record<string, unknown> | null) || {};
  return {
    id: String(a.id),
    timestamp: String(a.timestamp || new Date().toISOString()),
    severity: (a.severity as UiAlert['severity']) || 'medium',
    title: String(a.title || 'Alert'),
    description: String(a.description || ''),
    srcIp: String(a.srcIp || '—'),
    dstIp: String(a.dstIp || '—'),
    protocol: String(a.protocol || '—'),
    attackType: String(a.attackType || 'Unknown'),
    confidence: Number(a.confidence) || 0,
    model: String(a.model || 'NetGuard-ML'),
    status: (a.status as UiAlert['status']) || 'open',
    features: f as any,
    mitre: 'TBD',
    mitrePhase: '—',
    topShapFeatures: [],
    remediation: ['Run /api/forensics/alert/{id}/report for full remediation text', 'Contain source host at firewall if high confidence'],
  };
}

export default function Alerts({ onNavigate }: { onNavigate: (p: string) => void }) {
  const [rows, setRows] = useState<UiAlert[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [filterSev, setFilterSev] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  useEffect(() => {
    (async () => {
      try {
        const r = await apiFetch(`${API_BASE}/api/detection/alerts`);
        if (!r.ok) return;
        const j = (await r.json()) as { alerts: Record<string, unknown>[] };
        if (j.alerts?.length) setRows(j.alerts.map(normalizeFromApi));
      } catch {
        // failed to fetch alerts
      }
    })();
  }, []);

  const filtered = rows
    .filter(a => filterSev === 'all' || a.severity === filterSev)
    .filter(a => filterStatus === 'all' || a.status === filterStatus)
    .sort((a, b) => (severityOrder[a.severity as keyof typeof severityOrder] ?? 9) - (severityOrder[b.severity as keyof typeof severityOrder] ?? 9));

  const selectedAlert = rows.find(a => a.id === selected) || null;

  const severityCounts = rows.reduce((acc, a) => { acc[a.severity] = (acc[a.severity] || 0) + 1; return acc; }, {} as Record<string, number>);

  useEffect(() => {
    if (!selected) return;
    (async () => {
      try {
        const r = await apiFetch(`${API_BASE}/api/forensics/alert/${selected}/shap`);
        if (!r.ok) return;
        const j = (await r.json()) as { explanation: { top: { feature: string; value: number; shap: number }[] } };
        const top = (j.explanation?.top || []).slice(0, 5).map(t => ({
          feature: t.feature,
          value: t.value,
          shap: t.shap,
          direction: (t.shap >= 0 ? 'harmful' : 'benign') as 'harmful' | 'benign',
        }));
        if (!top.length) return;
        setRows(prev => prev.map(p => p.id === selected ? { ...p, topShapFeatures: top } : p));
      } catch { /* optional */ }
    })();
  }, [selected]);

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex-shrink-0 p-4 md:px-6 md:pt-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-red-400" /> Alert Center
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              AI-prioritized security events · MITRE ATT&CK mapped · Confidence-scored
            </p>
          </div>
          <div className="flex gap-2">
            <a
              href={`${API_BASE}/api/forensics/export/csv`}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#111827] border border-[#243244] rounded-md text-xs text-slate-300 hover:text-white hover:border-[#06B6D4]/50 transition-colors"
            >
              <Download className="w-3.5 h-3.5" /> Export CSV
            </a>
            <button className="flex items-center gap-1.5 px-3 py-1.5 bg-[#111827] border border-[#243244] rounded-md text-xs text-slate-300 hover:text-white hover:border-[#06B6D4]/50 transition-colors">
              <Filter className="w-3.5 h-3.5" /> Filter
            </button>
          </div>
        </div>

        {/* Severity summary */}
        <div className="grid grid-cols-4 gap-2">
          {[
            { sev: 'critical', label: 'Critical', border: 'border-red-500/30', bg: 'bg-red-500/5', color: 'text-red-400' },
            { sev: 'high', label: 'High', border: 'border-orange-500/30', bg: 'bg-orange-500/5', color: 'text-orange-400' },
            { sev: 'medium', label: 'Medium', border: 'border-yellow-500/30', bg: 'bg-yellow-500/5', color: 'text-yellow-400' },
            { sev: 'low', label: 'Low', border: 'border-blue-500/30', bg: 'bg-blue-500/5', color: 'text-blue-400' },
          ].map(s => (
            <button key={s.sev} onClick={() => setFilterSev(filterSev === s.sev ? 'all' : s.sev)}
              className={`p-2.5 rounded-lg border ${s.border} ${s.bg} text-center transition-all ${filterSev === s.sev ? 'ring-1 ring-[#06B6D4]' : 'hover:opacity-90'}`}>
              <p className={`text-lg font-bold font-mono ${s.color}`}>{severityCounts[s.sev] || 0}</p>
              <p className="text-xs text-slate-400 mt-0.5">{s.label}</p>
            </button>
          ))}
        </div>

        {/* Filters */}
        <div className="flex gap-2 flex-wrap">
          <select
            value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
            className="text-xs bg-[#0F172A] border border-[#243244] rounded-md px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-[#06B6D4]"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="escalated">Escalated</option>
            <option value="closed">Closed</option>
          </select>
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <span>{filtered.length} alerts shown</span>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className={`flex-1 overflow-hidden flex gap-4 px-4 md:px-6 pb-4 md:pb-6 ${selected ? 'flex-col lg:flex-row' : ''}`}>
        {/* Alert list */}
        <div className={`overflow-y-auto space-y-2 ${selected ? 'lg:w-1/2 lg:flex-shrink-0' : 'w-full'}`}>
          {filtered.map(alert => {
            const isSelected = selected === alert.id;
            return (
              <div
                key={alert.id}
                onClick={() => setSelected(isSelected ? null : alert.id)}
                className={`p-3 md:p-4 rounded-lg border cursor-pointer transition-colors ${
                  alert.severity === 'critical' ? 'border-red-500/30 bg-red-950/20 hover:bg-red-950/30' :
                  alert.severity === 'high' ? 'border-orange-500/30 bg-orange-950/15 hover:bg-orange-950/25' :
                  'border-[#243244] bg-[#111827] hover:bg-[#151f33]'
                } ${isSelected ? 'ring-1 ring-[#06B6D4]' : ''}`}
              >
                <div className="flex items-start gap-3">
                  <AlertTriangle className={`w-4 h-4 flex-shrink-0 mt-0.5 ${
                    alert.severity === 'critical' ? 'text-red-400' :
                    alert.severity === 'high' ? 'text-orange-400' : 'text-yellow-400'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <StatusBadge status={alert.severity} size="xs" />
                      <span className="text-xs font-mono text-slate-500">{alert.id}</span>
                      <StatusBadge status={alert.status} size="xs" />
                    </div>
                    <h4 className="text-sm font-semibold text-white">{alert.title}</h4>
                    <p className="text-xs text-slate-400 mt-1 line-clamp-2">{alert.description}</p>
                    <div className="flex flex-wrap items-center gap-3 mt-2 text-xs">
                      <span className="font-mono text-[#06B6D4]">{alert.srcIp} → {alert.dstIp}</span>
                      <span className="text-slate-500">{alert.attackType}</span>
                      <span className="font-mono text-emerald-400">{alert.confidence}% conf</span>
                      <span className="text-slate-500 font-mono">{alert.model}</span>
                      <span className="text-slate-500 bg-[#0F172A] border border-[#243244] px-1.5 py-0.5 rounded text-xs">{alert.mitre}</span>
                    </div>
                  </div>
                  <div className="flex-shrink-0 text-slate-500">
                    {isSelected ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Alert Detail Panel */}
        {selectedAlert && (
          <div className="lg:flex-1 overflow-y-auto space-y-4">
            <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <StatusBadge status={selectedAlert.severity} size="sm" />
                    <span className="text-xs font-mono text-slate-400">{selectedAlert.id}</span>
                    <span className="text-xs bg-[#0F172A] border border-[#243244] text-slate-300 px-2 py-0.5 rounded font-mono">{selectedAlert.mitre}</span>
                  </div>
                  <h3 className="text-base font-bold text-white">{selectedAlert.title}</h3>
                  <p className="text-xs text-slate-400 mt-1">{selectedAlert.description}</p>
                </div>
              </div>

              {/* Alert metadata */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2.5 mb-4">
                {[
                  { label: 'Attack Type', value: selectedAlert.attackType },
                  { label: 'Protocol', value: selectedAlert.protocol },
                  { label: 'MITRE Phase', value: selectedAlert.mitrePhase },
                  { label: 'ML Model', value: selectedAlert.model },
                  { label: 'Confidence', value: `${selectedAlert.confidence}%` },
                  { label: 'Status', value: selectedAlert.status },
                ].map(m => (
                  <div key={m.label} className="bg-[#0F172A] border border-[#243244] rounded-md p-2.5">
                    <p className="text-[11px] text-slate-500">{m.label}</p>
                    <p className="text-xs font-semibold text-white mt-0.5 font-mono">{m.value}</p>
                  </div>
                ))}
              </div>

              {/* SHAP Feature Bars */}
              <div className="mb-4">
                <h5 className="text-xs font-semibold text-white mb-2 flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-purple-400" /> SHAP Feature Attribution (Top 5)
                </h5>
                <div className="space-y-2">
                  {(!selectedAlert.topShapFeatures || selectedAlert.topShapFeatures.length === 0) && (
                    <p className="text-xs text-slate-500">SHAP not loaded. Select an alert; values load from the API.</p>
                  )}
                  {selectedAlert.topShapFeatures?.map(f => (
                    <div key={f.feature} className="space-y-0.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-mono text-slate-300">{f.feature}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-slate-500">val: {typeof f.value === 'number' ? f.value.toFixed ? f.value.toFixed(2) : f.value : f.value}</span>
                          <span className={`font-mono font-bold ${f.direction === 'harmful' ? 'text-red-400' : 'text-emerald-400'}`}>
                            {f.direction === 'harmful' ? '+' : ''}{f.shap.toFixed(2)}
                          </span>
                        </div>
                      </div>
                      <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${f.direction === 'harmful' ? 'bg-red-500' : 'bg-emerald-500'}`}
                          style={{ width: `${Math.min((Math.abs(f.shap) / 3.5) * 100, 100)}%`, opacity: 0.8 }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
                <p className="text-xs text-slate-500 mt-2 italic">
                  → Click <button onClick={() => onNavigate('forensics')} className="text-cyan-400 hover:underline">Forensics</button> for full SHAP waterfall plot & LLM explanation
                </p>
              </div>

              {/* Flow Features */}
              <div className="mb-4">
                <h5 className="text-xs font-semibold text-white mb-2">Extracted Flow Features</h5>
                <div className="grid grid-cols-2 gap-2">
                  {Object.entries(selectedAlert.features || {}).map(([k, v]) => (
                    <div key={k} className="flex items-center justify-between bg-[#0F172A] border border-[#243244] rounded px-2.5 py-1.5">
                      <span className="text-[11px] font-mono text-slate-400">{k}</span>
                      <span className="text-[11px] font-mono text-[#06B6D4]">{typeof v === 'number' && v > 1000 ? (v / 1000).toFixed(1) + 'K' : String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Remediation */}
              <div>
                <h5 className="text-xs font-semibold text-white mb-2 flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-emerald-400" /> Recommended Remediation
                </h5>
                <ol className="space-y-1.5">
                  {(selectedAlert.remediation && selectedAlert.remediation.length ? selectedAlert.remediation : [
                    'Generate: POST /api/forensics/alert/{id}/report for LLM/SHAP bundle',
                    'Block or isolate the source/destination as appropriate to severity',
                  ]).map((r, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs">
                      <span className="flex-shrink-0 w-4 h-4 rounded bg-emerald-500/10 text-emerald-400 text-xs flex items-center justify-center font-bold mt-0.5 border border-emerald-500/20">{i + 1}</span>
                      <span className="text-slate-300">{r}</span>
                    </li>
                  ))}
                </ol>
              </div>

              {/* Timestamps */}
              <div className="mt-4 flex items-center gap-2 text-xs text-slate-500 border-t border-[#243244] pt-3">
                <Clock className="w-3.5 h-3.5" />
                <span>Detected: <span className="font-mono text-slate-400">{new Date(selectedAlert.timestamp).toLocaleString()}</span></span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
