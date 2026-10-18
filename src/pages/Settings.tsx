import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Settings as SettingsIcon, Wifi, Cpu, Database, Shield, Bell, Key, RefreshCw, FlaskConical } from 'lucide-react';
import { fetchDashboardConfig, fetchDashboardStats, fetchHealth, postDemoLoadSample } from '../api/dashboard';
import { fetchCaptureInterfaces, fetchCaptureStatus, type CaptureInterface } from '../api/capture';
import { API_BASE } from '../api/config';

interface ToggleProps {
  label: string;
  description?: string;
  defaultChecked?: boolean;
}

function Toggle({ label, description, defaultChecked = false }: ToggleProps) {
  return (
    <div className="flex items-start justify-between gap-4 py-3 border-b border-slate-800/60 last:border-0">
      <div>
        <p className="text-xs font-medium text-white">{label}</p>
        {description && <p className="text-xs text-slate-500 mt-0.5">{description}</p>}
      </div>
      <div className={`flex-shrink-0 w-10 h-5 rounded-full relative cursor-pointer transition-colors ${defaultChecked ? 'bg-cyan-600' : 'bg-slate-600'}`}>
        <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${defaultChecked ? 'translate-x-5' : 'translate-x-0.5'}`} />
      </div>
    </div>
  );
}

function Section({ title, icon: Icon, children }: { title: string; icon: typeof SettingsIcon; children: ReactNode }) {
  return (
    <div className="bg-[#111827] border border-[#243244] rounded-lg p-4">
      <h4 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
        <Icon className="w-4 h-4 text-[#06B6D4]" />
        {title}
      </h4>
      {children}
    </div>
  );
}

export default function Settings() {
  const [cfg, setCfg] = useState<Record<string, unknown> | null>(null);
  const [stats, setStats] = useState<{ alertsTotal: number; hosts: number; flows: number; packets: number; visibilitySource: string } | null>(null);
  const [health, setHealth] = useState<string>('—');
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [ifaces, setIfaces] = useState<CaptureInterface[]>([]);
  const [iface, setIface] = useState('');
  const [captureRunning, setCaptureRunning] = useState(false);
  const [captureDetail, setCaptureDetail] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setErr(null);
    try {
      const [c, s, h, ifaceRes, capSt] = await Promise.all([
        fetchDashboardConfig(),
        fetchDashboardStats(),
        fetchHealth(),
        fetchCaptureInterfaces().catch(() => null),
        fetchCaptureStatus().catch(() => null),
      ]);
      setCfg(c);
      setStats(s);
      setHealth(h.status || 'ok');
      if (ifaceRes) {
        setIfaces(ifaceRes.interfaces || []);
        setCaptureDetail(ifaceRes.tsharkDetail ?? ifaceRes.error ?? null);
        setIface((prev) => {
          if (prev && ifaceRes.interfaces.some((i) => i.id === prev || i.name === prev)) return prev;
          return ifaceRes.interfaces.find((i) => !i.isLoopback)?.id || ifaceRes.interfaces[0]?.id || '';
        });
      }
      setCaptureRunning(!!capSt?.running);
    } catch (e) {
      setErr((e as Error).message);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const demo = async (withMl: boolean) => {
    setBusy(withMl ? 'demo+ml' : 'demo');
    setErr(null);
    try {
      await postDemoLoadSample(withMl);
      await refresh();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="p-4 md:p-6 space-y-4 overflow-auto h-full">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <SettingsIcon className="w-5 h-5 text-slate-400" /> Platform Configuration
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">Live backend status below · toggles are UI-only (persist in a future release)</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <button
            type="button"
            onClick={() => void refresh()}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs border border-slate-600 text-slate-300 hover:bg-slate-800"
          >
            <RefreshCw className="w-3 h-3" /> Refresh status
          </button>
          <button
            type="button"
            disabled={!!busy}
            onClick={() => void demo(false)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50"
          >
            <FlaskConical className="w-3 h-3" /> {busy === 'demo' ? '…' : 'Load demo PCAP'}
          </button>
          <button
            type="button"
            disabled={!!busy}
            onClick={() => void demo(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs border border-purple-500/40 bg-purple-500/10 text-purple-300 hover:bg-purple-500/20 disabled:opacity-50"
          >
            {busy === 'demo+ml' ? '…' : 'Demo PCAP + ML scan'}
          </button>
        </div>
      </div>

      {err && (
        <div className="text-xs text-amber-400 border border-amber-500/20 rounded-lg px-3 py-2 bg-amber-500/5">
          {err} — start backend: <code className="text-cyan-300">python run_backend.py</code>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="bg-slate-900/80 border border-slate-700/60 rounded-xl p-4 text-xs space-y-2">
          <p className="text-slate-400 font-semibold text-sm text-white mb-2">Runtime</p>
          <p><span className="text-slate-500">API health:</span> <span className="text-emerald-400 font-mono">{health}</span></p>
          <p><span className="text-slate-500">Visibility source:</span> <span className="text-slate-200 font-mono">{stats?.visibilitySource ?? '—'}</span></p>
          <p><span className="text-slate-500">Live capture:</span> <span className={`font-mono ${captureRunning ? 'text-emerald-400' : 'text-slate-200'}`}>{captureRunning ? 'running' : 'idle'}</span></p>
          <p><span className="text-slate-500">Hosts / flows / packets:</span>{' '}
            <span className="text-slate-200 font-mono">{stats?.hosts ?? '—'} / {stats?.flows ?? '—'} / {stats?.packets ?? '—'}</span></p>
          <p><span className="text-slate-500">Alerts in DB:</span> <span className="text-slate-200 font-mono">{stats?.alertsTotal ?? '—'}</span></p>
          <p><span className="text-slate-500">OpenAI:</span> <span className="text-slate-200 font-mono">{cfg?.openaiConfigured ? 'configured' : 'not set (offline LLM)'}</span></p>
        </div>
        <div className="bg-slate-900/80 border border-slate-700/60 rounded-xl p-4 text-xs space-y-2 overflow-hidden">
          <p className="text-slate-400 font-semibold text-sm text-white mb-2">Paths</p>
          <p className="truncate"><span className="text-slate-500">DB:</span> <span className="text-cyan-300/90 font-mono break-all">{String(cfg?.databaseUrl ?? '—')}</span></p>
          <p className="truncate"><span className="text-slate-500">Models:</span> <span className="text-cyan-300/90 font-mono">{String(cfg?.modelDir ?? '—')}</span></p>
          <p className="text-slate-500 mt-2">Exports: <a className="text-cyan-400 hover:underline" href={`${API_BASE}/api/forensics/export/csv`}>CSV alerts</a></p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Section title="Network Capture" icon={Wifi}>
          <div className="space-y-3">
            <div>
              <label htmlFor="settings-iface" className="text-xs text-slate-400 block mb-1">Primary Interface (live capture)</label>
              <div className="flex gap-2">
                <select
                  id="settings-iface"
                  value={iface}
                  onChange={(e) => setIface(e.target.value)}
                  className="flex-1 bg-slate-800 border border-slate-700/60 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
                >
                  {!ifaces.length && <option value="">No interfaces — refresh or install Wireshark</option>}
                  {ifaces.map((i) => (
                    <option key={i.id || i.name} value={i.id || i.name}>
                      {i.id ? `${i.id}. ` : ''}{i.description || i.name}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  aria-label="Refresh capture interfaces"
                  onClick={() => void refresh()}
                  className="px-2.5 py-2 rounded-lg border border-slate-600 text-slate-300 hover:bg-slate-800"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                Start/stop live capture from the <span className="text-cyan-400">Visibility</span> page.
                Install Npcap and run the backend with administrator privileges if required.
              </p>
              {captureDetail && (
                <p className="text-xs text-amber-400/90 mt-1">{captureDetail}</p>
              )}
            </div>
            <Toggle label="Enable Passive Mode" description="Never inject packets into the network" defaultChecked={true} />
            <Toggle label="PCAP Auto-Save" description="Uploads stored under data/uploads/" defaultChecked={true} />
            <Toggle label="DNS Metadata Extraction" description="Passive DNS query logging" defaultChecked={true} />
            <Toggle label="TLS SNI Extraction" description="ClientHello parsing (no decryption)" defaultChecked={true} />
          </div>
        </Section>

        <Section title="AI/ML Models" icon={Cpu}>
          <div className="space-y-3">
            <p className="text-xs text-slate-400">
              Bundled models live under <span className="font-mono text-cyan-400">data/models/</span>. Run <span className="font-mono">POST /api/detection/scan</span> from Detection or use &quot;Demo PCAP + ML scan&quot; here.
            </p>
            <Toggle label="Anomaly Detection (IsoForest)" description="Parallel with RF/XGB ensemble" defaultChecked={true} />
            <Toggle label="SHAP Explanations" description="Computed on demand in Forensics" defaultChecked={true} />
          </div>
        </Section>

        <Section title="LLM Integration" icon={Key}>
          <div className="space-y-3">
            <p className="text-xs text-slate-500">
              Set <span className="font-mono text-cyan-400">NETGUARD_OPENAI_KEY</span> on the backend for OpenAI-backed chat and reports. Otherwise deterministic templates are used.
            </p>
            <Toggle label="Enable LLM Reports" description="POST /api/forensics/alert/{id}/report" defaultChecked={true} />
            <Toggle label="Analyst Chat" description="POST /api/forensics/chat" defaultChecked={true} />
          </div>
        </Section>

        <Section title="Alert & Notification" icon={Bell}>
          <div className="space-y-3">
            <p className="text-xs text-slate-500">Slack / email hooks are not wired in this build — use CSV export or your SIEM.</p>
            <Toggle label="Real-time Dashboard Alerts" description="Poll API from browser" defaultChecked={true} />
          </div>
        </Section>

        <Section title="Database" icon={Database}>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-xs">
              {[
                { label: 'Alerts stored', value: stats ? String(stats.alertsTotal) : '—' },
                { label: 'Hosts (snapshot)', value: stats ? String(stats.hosts) : '—' },
                { label: 'Flows (snapshot)', value: stats ? String(stats.flows) : '—' },
                { label: 'Engine', value: 'SQLite' },
              ].map((s) => (
                <div key={s.label} className="bg-slate-800/60 rounded-lg p-2">
                  <p className="text-slate-400">{s.label}</p>
                  <p className="text-white font-mono font-semibold">{s.value}</p>
                </div>
              ))}
            </div>
            <Toggle label="Auto-Purge Old Records" description="Not implemented in demo" defaultChecked={false} />
          </div>
        </Section>

        <Section title="Platform Security" icon={Shield}>
          <div className="space-y-3">
            <p className="text-xs text-slate-500">
              Production: set <span className="font-mono text-cyan-400">NETGUARD_API_TOKEN</span> and matching{' '}
              <span className="font-mono text-cyan-400">VITE_NETGUARD_API_TOKEN</span>; restrict{' '}
              <span className="font-mono text-cyan-400">NETGUARD_ALLOWED_ORIGINS</span>; bind to localhost or a reverse proxy with HTTPS.
            </p>
            <Toggle label="Audit Logging" description="Server logs to stdout" defaultChecked={true} />
            <div className="mt-2 p-2.5 bg-emerald-950/30 border border-emerald-500/20 rounded-lg">
              <p className="text-xs text-emerald-400 font-semibold">Passive capture mode</p>
              <p className="text-xs text-slate-400 mt-0.5">No active probing · CORS defaults to localhost Vite origins</p>
            </div>
          </div>
        </Section>
      </div>

      <div className="flex justify-end gap-3">
        <button type="button" className="px-4 py-2 bg-slate-800 border border-slate-700/60 text-slate-300 rounded-lg text-sm hover:text-white">
          Reset to Defaults
        </button>
        <button type="button" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm">
          Save Configuration
        </button>
      </div>
    </div>
  );
}
