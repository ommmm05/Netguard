import { useEffect, useState } from 'react';
import { Cpu, Target, BarChart3, GitBranch, Layers } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  Cell
} from 'recharts';
import { API_BASE, apiFetch } from '../api/config';
import { fetchModelMetrics, fetchDashboardOverview, fetchTrainStatus, type ModelMetrics } from '../api/dashboard';
import MetricCard from '../components/shared/MetricCard';

const tabs = ['Overview', 'Model Evaluation', 'Feature Importance', 'Attack Analysis', 'Dataset Stats', 'Live Inference'];

type LiveRow = {
  time: string;
  srcIp: string;
  dstIp: string;
  proto: string;
  prediction: string;
  confidence: number;
  model: string;
  latency: string;
  severity: string;
};

function PendingMetric({ label, sub }: { label: string; sub?: string }) {
  return (
    <div className="bg-[#111827] border border-amber-500/20 rounded-lg p-3 text-center">
      <p className="text-xl font-bold font-mono text-amber-400">—</p>
      <p className="text-xs text-white font-medium mt-1">{label}</p>
      <p className="text-[11px] text-amber-500/80 mt-0.5">{sub ?? 'Pending real training'}</p>
    </div>
  );
}

function parseApiDetail(j: unknown, fallback: string): string {
  if (j && typeof j === 'object' && 'detail' in j) {
    const d = (j as { detail: unknown }).detail;
    if (Array.isArray(d)) return d.map((x) => (typeof x === 'object' && x && 'msg' in x ? String((x as { msg: unknown }).msg) : JSON.stringify(x))).join('; ');
    if (typeof d === 'string') return d;
    return JSON.stringify(d);
  }
  return fallback;
}
export default function Detection() {
  const [detStatus, setDetStatus] = useState<Record<string, unknown> | null>(null);
  const [scanMsg, setScanMsg] = useState<string>('');
  const [scanBusy, setScanBusy] = useState(false);
  const [liveRows, setLiveRows] = useState<LiveRow[] | null>(null);
  const [liveLoading, setLiveLoading] = useState(false);
  const [liveSource, setLiveSource] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [activeModelKey, setActiveModelKey] = useState<'xgb' | 'rf'>('xgb');

  const [modelMeta, setModelMeta] = useState<ModelMetrics | null>(null);
  const [atkDist, setAtkDist] = useState<{ attack: string; count: number; color: string }[]>([]);
  const [fi, setFi] = useState<{ feature: string; importance: number; category?: string; source?: string }[]>([]);
  const [trainStatus, setTrainStatus] = useState<{ state: string; message: string; progress: number } | null>(null);

  // Fetch real model metrics
  useEffect(() => {
    fetchModelMetrics()
      .then(setModelMeta)
      .catch(() => setModelMeta(null));
  }, [scanMsg]);

  // Fetch attack distribution from dashboard overview
  useEffect(() => {
    fetchDashboardOverview()
      .then((d) => setAtkDist(d.attackDistribution ?? []))
      .catch(() => {});
  }, [scanMsg]);

  // Fetch real feature importance
  useEffect(() => {
    apiFetch(`${API_BASE}/api/forensics/feature-importance`)
      .then((r) => r.ok ? r.json() : null)
      .then((j: any) => { if (j?.items?.length) setFi(j.items); })
      .catch(() => {});
  }, []);

  // Poll training status when in progress
  useEffect(() => {
    if (!trainStatus || trainStatus.state === 'done' || trainStatus.state === 'idle' || trainStatus.state === 'error') return;
    const t = setInterval(() => {
      fetchTrainStatus().then(setTrainStatus).catch(() => {});
    }, 2000);
    return () => clearInterval(t);
  }, [trainStatus]);

  useEffect(() => {
    (async () => {
      try {
        const r = await apiFetch(`${API_BASE}/api/detection/status`);
        if (r.ok) setDetStatus(await r.json());
      } catch { /* ignore */ }
    })();
  }, [scanMsg]);

  useEffect(() => {
    if (activeTab !== 5) return;
    let cancel = false;
    (async () => {
      setLiveLoading(true);
      try {
        const r = await apiFetch(`${API_BASE}/api/detection/live-stream`);
        if (!r.ok) return;
        const j = (await r.json()) as { source: string; items: any[] };
        if (!cancel && j.items) {
          setLiveRows(j.items);
          setLiveSource(j.source);
        }
      } catch { /* optional */ }
      finally {
        if (!cancel) setLiveLoading(false);
      }
    })();
    return () => { cancel = true; };
  }, [activeTab]);

  const runScan = async () => {
    setScanBusy(true);
    setScanMsg('');
    try {
      const r = await apiFetch(`${API_BASE}/api/detection/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ min_confidence: 0.4, clear_existing: false }),
      });
      let j: any = {};
      try { j = await r.json(); } catch { j = {}; }
      if (!r.ok) throw new Error(parseApiDetail(j, r.statusText));
      setScanMsg(`Created ${j.created || 0} alerts (evaluated ${j.evaluated || 0} flows).`);
    } catch (e) {
      setScanMsg((e as Error).message);
    } finally {
      setScanBusy(false);
    }
  };

  const isReal = modelMeta?.isRealTraining === true;

  return (
    <div className="p-4 md:p-6 space-y-4 overflow-auto h-full">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Cpu className="w-5 h-5 text-[#06B6D4]" /> AI Threat Detection Module
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Trained on <span className="text-[#06B6D4] font-mono">CICIDS2017</span> ·{' '}
            <span className="text-[#06B6D4] font-mono">Random Forest</span> + <span className="text-[#06B6D4] font-mono">XGBoost</span> + <span className="text-[#06B6D4] font-mono">Isolation Forest</span>
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap justify-end">
          <div className="flex items-center gap-2 bg-[#111827] border border-[#243244] rounded-md px-3 py-1.5">
            <div className="w-2 h-2 rounded-full bg-emerald-400" />
            <span className="text-xs text-slate-300 font-mono">detection/{detStatus?.ok ? 'models ok' : '—'}</span>
          </div>
          <button
            type="button"
            onClick={() => void runScan()}
            disabled={scanBusy}
            className="px-3 py-1.5 rounded-md text-xs font-medium bg-[#06B6D4] hover:bg-[#0891b2] text-slate-950 transition-colors disabled:opacity-50"
          >
            {scanBusy ? 'Scanning…' : 'Run detection scan'}
          </button>
        </div>
      </div>
      {scanMsg && (
        <p className="text-xs text-slate-400 font-mono border border-[#243244] rounded-md px-3 py-2 bg-[#111827]">{scanMsg}</p>
      )}

      {/* Model KPIs */}
      {modelMeta?.warning && (
        <div className="text-xs text-amber-400 bg-amber-500/5 border border-amber-500/20 rounded-md px-3 py-2">
          {modelMeta.warning}
        </div>
      )}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {isReal && modelMeta?.xgb ? (
          <MetricCard title="XGBoost Accuracy" value={`${modelMeta.xgb.accuracy}%`} icon={Target} iconColor="text-purple-400" subtitle={`F1: ${modelMeta.xgb.f1}%`} />
        ) : <PendingMetric label="XGBoost Accuracy" />}
        {isReal && modelMeta?.rf ? (
          <MetricCard title="Random Forest Acc." value={`${modelMeta.rf.accuracy}%`} icon={GitBranch} iconColor="text-[#06B6D4]" subtitle={`F1: ${modelMeta.rf.f1}%`} />
        ) : <PendingMetric label="Random Forest Accuracy" />}
        <MetricCard title="Model Status" value={isReal ? 'Real Training' : 'Synthetic'} icon={Layers} iconColor={isReal ? "text-emerald-400" : "text-amber-400"} subtitle={isReal ? 'Ready for production' : 'Fallback mode'} />
        <MetricCard title="Features Used" value={modelMeta?.nFeatures ?? 0} icon={BarChart3} iconColor="text-blue-400" subtitle="CICIDS subset" />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0F172A] border border-[#243244] rounded-lg p-1 flex-wrap">
        {tabs.map((tab, i) => (
          <button key={tab} onClick={() => setActiveTab(i)}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${activeTab === i ? 'bg-[#06B6D4]/10 text-[#06B6D4] border border-[#06B6D4]/30' : 'text-slate-400 hover:text-slate-200'}`}>
            {tab}
          </button>
        ))}
      </div>

      {activeTab === 0 && (
        <div className="grid grid-cols-1 gap-4">
          {/* Metric summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: 'XGBoost Accuracy', value: modelMeta?.xgb ? `${modelMeta.xgb.accuracy}%` : '—', sub: 'Multi-class OvR', color: 'text-purple-400' },
              { label: 'RF Accuracy', value: modelMeta?.rf ? `${modelMeta.rf.accuracy}%` : '—', sub: 'Multi-class OvR', color: 'text-[#06B6D4]' },
              { label: 'Features Extracted', value: modelMeta?.nFeatures ? modelMeta.nFeatures.toString() : '—', sub: 'Live parsing', color: 'text-yellow-400' },
              { label: 'Train Samples', value: modelMeta?.trainInfo?.nTrain ? modelMeta.trainInfo.nTrain.toString() : '—', sub: 'Total flows', color: 'text-emerald-400' },
            ].map(m => (
              <div key={m.label} className="bg-[#111827] border border-[#243244] rounded-lg p-3 text-center">
                <p className={`text-xl font-bold font-mono ${m.color}`}>{m.value}</p>
                <p className="text-xs text-white font-medium mt-1">{m.label}</p>
                <p className="text-[11px] text-slate-500 mt-0.5">{m.sub}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 1 && (
        <div className="space-y-4">
          <div className="flex gap-2">
            <button onClick={() => setActiveModelKey('xgb')} className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${activeModelKey === 'xgb' ? 'bg-[#06B6D4]/10 text-[#06B6D4] border border-[#06B6D4]/30' : 'bg-[#111827] border border-[#243244] text-slate-400'}`}>XGBoost</button>
            <button onClick={() => setActiveModelKey('rf')} className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${activeModelKey === 'rf' ? 'bg-[#06B6D4]/10 text-[#06B6D4] border border-[#06B6D4]/30' : 'bg-[#111827] border border-[#243244] text-slate-400'}`}>Random Forest</button>
          </div>
          <div className="bg-[#111827] border border-[#243244] rounded-lg p-4 md:p-6">
            {modelMeta?.[activeModelKey] && modelMeta.classes ? (
              <>
                <h4 className="text-sm font-semibold text-white mb-1">{activeModelKey === 'xgb' ? 'XGBoost' : 'Random Forest'} — Model Evaluation</h4>
                <p className="text-xs text-slate-500 mb-4">
                  Accuracy: <span className="text-emerald-400 font-mono">{modelMeta[activeModelKey]?.accuracy || 0}%</span> ·
                  Precision: <span className="text-blue-400 font-mono">{modelMeta[activeModelKey]?.precision || 0}%</span> ·
                  Recall: <span className="text-cyan-400 font-mono">{modelMeta[activeModelKey]?.recall || 0}%</span> ·
                  F1: <span className="text-purple-400 font-mono">{modelMeta[activeModelKey]?.f1 || 0}%</span>
                </p>
                <div className="bg-slate-900 border border-slate-700/50 rounded-lg p-3">
                  <p className="text-xs text-slate-400 mb-2">Detailed Class Metrics (via classification_report):</p>
                  <pre className="text-[10px] font-mono text-slate-300 whitespace-pre-wrap overflow-x-auto">
                    {JSON.stringify(modelMeta[activeModelKey]?.report || {}, null, 2)}
                  </pre>
                </div>
              </>
            ) : (
              <div className="text-center py-6 text-slate-400">
                Pending real model evaluation. Train the model to see evaluation metrics.
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 2 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
            <h4 className="text-sm font-semibold text-white mb-1">Global Feature Importance</h4>
            <p className="text-xs text-slate-500 mb-3">Top 15 features — from real Random Forest</p>
            {fi.length > 0 ? (
              <ResponsiveContainer width="100%" height={320}>
                <BarChart data={fi.slice(0, 15)} layout="vertical" margin={{ left: 10, right: 30, top: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} tickFormatter={(v) => v.toFixed(2)} />
                  <YAxis dataKey="feature" type="category" tick={{ fill: '#94a3b8', fontSize: 9 }} width={120} fontFamily="monospace" />
                  <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #243244', borderRadius: 6, fontSize: 11 }} formatter={(v: any) => [v.toFixed(4), 'Importance']} />
                  <Bar dataKey="importance" radius={[0, 3, 3, 0]} name="Importance">
                    {fi.slice(0, 15).map((_, i) => (
                      <Cell key={i} fill={`hsl(${210 - i * 15}, 70%, ${55 - i * 2}%)`} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex flex-col items-center justify-center h-48 text-center">
                <p className="text-xs text-slate-500">Feature importance unavailable.</p>
              </div>
            )}
          </div>
          <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
            <h4 className="text-sm font-semibold text-white mb-3">Feature Map</h4>
            <div className="space-y-2">
              {fi.length > 0 ? fi.slice(0, 8).map((f) => (
                <div key={f.feature} className="p-3 bg-[#0F172A] border border-[#243244] rounded-md flex items-center justify-between">
                  <div>
                    <span className="text-xs font-mono text-[#06B6D4]">{f.feature}</span>
                    <p className="text-[10px] text-slate-500 mt-0.5">Category: {f.category}</p>
                  </div>
                  <span className="text-xs font-mono text-emerald-400">{(f.importance * 100).toFixed(1)}%</span>
                </div>
              )) : (
                <p className="text-xs text-slate-500 text-center py-4">No data.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {activeTab === 3 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
            <h4 className="text-sm font-semibold text-white mb-1">Attack Detection Rate by Type</h4>
            <p className="text-xs text-slate-500 mb-3">Counts from live inference pipeline</p>
            {atkDist.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={atkDist} margin={{ top: 0, right: 10, left: -10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="attack" tick={{ fill: '#94a3b8', fontSize: 9 }} angle={-20} textAnchor="end" height={40} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 10 }} />
                  <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #243244', borderRadius: 6, fontSize: 11 }} />
                  <Bar dataKey="count" radius={[3, 3, 0, 0]} name="Detections">
                    {atkDist.map((e, i) => <Cell key={i} fill={e.color || '#3b82f6'} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex flex-col items-center justify-center h-48 text-center">
                <p className="text-xs text-slate-500">No attack detections available.</p>
                <p className="text-xs text-[#06B6D4] mt-1 cursor-pointer hover:underline" onClick={runScan}>Run detection scan</p>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 4 && (
        <div className="grid grid-cols-1 gap-4">
          <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
            <h4 className="text-sm font-semibold text-white mb-1">CICIDS2017 Dataset Statistics</h4>
            <p className="text-xs text-slate-500 mb-3">Sourced from real model_meta.json</p>
            {isReal ? (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                {[
                  { label: 'Training Samples', value: modelMeta?.trainInfo?.nTrain?.toLocaleString() ?? '—', color: 'text-[#06B6D4]' },
                  { label: 'Test Samples', value: modelMeta?.trainInfo?.nTest?.toLocaleString() ?? '—', color: 'text-purple-400' },
                  { label: 'Features', value: modelMeta?.nFeatures ?? '—', color: 'text-emerald-400' },
                  { label: 'Attack Classes', value: modelMeta?.classes?.length ?? '—', color: 'text-red-400' },
                ].map(s => (
                  <div key={s.label} className="bg-[#0F172A] border border-[#243244] rounded-md p-2.5 text-center">
                    <p className={`text-lg font-bold font-mono ${s.color}`}>{s.value}</p>
                    <p className="text-xs text-slate-400">{s.label}</p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-6">
                <p className="text-sm text-amber-400 mb-2">No real CICIDS2017 training data found.</p>
                <p className="text-xs text-slate-500 max-w-md mx-auto">Upload a real CICIDS2017 CSV via the Settings page or the API to populate dataset statistics and achieve real-world evaluation metrics.</p>
              </div>
            )}
          </div>
          <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
            <h4 className="text-sm font-semibold text-white mb-3">ML Pipeline — Feature Engineering</h4>
            <div className="space-y-2">
              {[
                { step: '1. Raw PCAP / CSV Ingestion', file: 'preprocessing.py', desc: 'Load CICIDS2017 CSVs, normalize column names' },
                { step: '2. Data Cleaning', file: 'preprocessing.py', desc: 'Drop NaN/Inf, clip outliers, handle class imbalance' },
                { step: '3. Feature Selection', file: 'features.py', desc: 'Flow features extracted via Scapy passive capture' },
                { step: '4. Feature Scaling', file: 'preprocessing.py', desc: 'StandardScaler normalization per feature' },
                { step: '5. Model Training', file: 'trainer.py', desc: 'RF (200 trees) + XGBoost (150 est.) + IsoForest' },
                { step: '6. Evaluation', file: 'trainer.py', desc: 'Accuracy, Precision, Recall, F1, ROC-AUC, CM' },
                { step: '7. SHAP Explainability', file: 'shap_explain.py', desc: 'TreeSHAP per-prediction explanations' },
                { step: '8. Live Inference', file: 'inference.py', desc: 'Real-time flow classification < 2ms latency' },
              ].map((s, i) => (
                <div key={i} className="flex items-start gap-3 p-2.5 bg-[#0F172A] border border-[#243244] rounded-md">
                  <span className="text-xs font-bold text-[#06B6D4] font-mono w-4 flex-shrink-0 mt-0.5">{i + 1}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-semibold text-white">{s.step.replace(/^\d+\. /, '')}</p>
                    <p className="text-[11px] text-slate-500 mt-0.5">{s.desc}</p>
                  </div>
                  <span className="text-[11px] font-mono text-[#06B6D4] flex-shrink-0 bg-[#06B6D4]/10 border border-[#06B6D4]/20 px-2 py-0.5 rounded">{s.file}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === 5 && (
        <div className="bg-[#111827] border border-[#243244] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[#243244] flex items-center justify-between">
            <div>
              <h4 className="text-sm font-semibold text-white">Live Inference Stream — inference.py</h4>
              <p className="text-xs text-slate-500 mt-0.5">
                {liveSource ? <span className="text-[#06B6D4] font-mono">source: {liveSource}</span> : 'Real-time ML classification of network flows'}
              </p>
            </div>
            <div className="flex items-center gap-2 bg-[#0F172A] border border-[#243244] rounded-md px-2.5 py-1">
              <div className="w-2 h-2 rounded-full bg-emerald-400" />
              <span className="text-xs text-slate-300 font-mono">{liveLoading ? 'LOADING' : 'LIVE'}</span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#243244] bg-[#0F172A]">
                  {['Timestamp', 'Src IP', 'Dst IP', 'Proto', 'Prediction', 'Confidence', 'Model', 'Latency', 'Severity'].map(h => (
                    <th key={h} className="px-3 py-2.5 text-left text-slate-400 font-medium uppercase tracking-wider whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(liveRows ?? []).map((row, i) => (
                  <tr key={i} className={`border-b border-[#243244] hover:bg-[#151f33] ${row.severity === 'critical' ? 'bg-red-950/20' : row.severity === 'high' ? 'bg-orange-950/15' : ''}`}>
                    <td className="px-3 py-2 font-mono text-slate-400">{row.time}</td>
                    <td className="px-3 py-2 font-mono text-[#06B6D4]">{row.srcIp}</td>
                    <td className="px-3 py-2 font-mono text-slate-300">{row.dstIp}</td>
                    <td className="px-3 py-2"><span className="bg-[#0F172A] border border-[#243244] text-slate-300 px-1.5 py-0.5 rounded font-mono">{row.proto}</span></td>
                    <td className="px-3 py-2">
                      <span className={`font-semibold ${row.prediction === 'Benign' ? 'text-emerald-400' : 'text-red-400'}`}>{row.prediction}</span>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1.5">
                        <div className="w-12 h-1.5 bg-[#1e293b] rounded-full overflow-hidden">
                          <div className="h-full rounded-full bg-emerald-500" style={{ width: `${row.confidence}%` }} />
                        </div>
                        <span className="font-mono text-emerald-400">{row.confidence}%</span>
                      </div>
                    </td>
                    <td className="px-3 py-2 font-mono text-purple-400">{row.model}</td>
                    <td className="px-3 py-2 font-mono text-slate-400">{row.latency}</td>
                    <td className="px-3 py-2">
                      <span className={`font-mono text-xs px-2 py-0.5 rounded border ${row.severity === 'critical' ? 'border-red-500/30 bg-red-500/10 text-red-400' : row.severity === 'high' ? 'border-orange-500/30 bg-orange-500/10 text-orange-400' : 'border-[#243244] bg-[#0F172A] text-slate-400'}`}>
                        {row.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
