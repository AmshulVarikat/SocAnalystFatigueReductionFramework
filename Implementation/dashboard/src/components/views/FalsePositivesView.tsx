import { useState, useEffect } from 'react';
import { Virtuoso } from 'react-virtuoso';
import { ShieldOff, Trash2 } from 'lucide-react';

interface AlertPayload {
  _internal_id: number;
  rule_id: string;
  timestamp: string;
  src_ip?: string;
  dest_ip?: string;
  mitre_tactic?: string;
  asset_context?: any;
  threat_intel?: any;
}

const FalsePositivesView = () => {
  const [alerts, setAlerts] = useState<AlertPayload[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchFP = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/v1/alerts/false-positives');
      const data = await res.json();
      setAlerts(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFP();
  }, []);

  return (
    <div className="flex flex-col h-full">
      <header className="p-8 border-b border-slate-800/60 bg-slate-900/40 backdrop-blur-md sticky top-0 z-10">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-rose-500/10 rounded-2xl border border-rose-500/20">
            <ShieldOff className="text-rose-400" size={28} />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-slate-100 to-slate-400 tracking-tight">Filtered False Positives</h1>
            <p className="text-slate-400 text-sm mt-2 font-medium">Alerts suppressed by the classification engine</p>
          </div>
        </div>
      </header>

      <div className="grid grid-cols-12 gap-6 px-8 py-4 border-b border-slate-800/60 text-xs font-bold text-slate-500 uppercase tracking-widest bg-slate-900/80 sticky top-[105px] z-10 backdrop-blur-md">
        <div className="col-span-2">ID</div>
        <div className="col-span-3">Rule Name</div>
        <div className="col-span-3">Source / Dest IP</div>
        <div className="col-span-2">Detected At</div>
        <div className="col-span-2 text-right">Tactic</div>
      </div>

      <div className="flex-1 overflow-hidden relative bg-slate-900/20">
        {loading ? (
          <div className="absolute inset-0 flex items-center justify-center text-slate-500 flex-col gap-4">
            <div className="w-12 h-12 rounded-full border-2 border-slate-700 border-t-rose-500 animate-spin"></div>
            <p className="tracking-wide font-medium">Loading...</p>
          </div>
        ) : alerts.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center text-slate-500 flex-col gap-4">
            <Trash2 size={48} className="text-slate-700" />
            <p className="tracking-wide font-medium text-lg">No false positives found.</p>
          </div>
        ) : (
          <Virtuoso
            style={{ height: '100%' }}
            data={alerts}
            itemContent={(_, alert) => (
              <div 
                className="grid grid-cols-12 gap-6 px-8 py-5 border-b border-slate-800/40 hover:bg-slate-800/40 transition-all duration-200 items-center opacity-80 hover:opacity-100"
              >
                <div className="col-span-2 font-mono text-sm text-slate-500">
                  FP-{alert._internal_id}
                </div>
                <div className="col-span-3 text-sm font-semibold text-slate-300 truncate pr-4">
                  Rule {alert.rule_id}
                </div>
                <div className="col-span-3 text-sm font-mono text-slate-400">
                  {alert.src_ip || 'N/A'} &rarr; {alert.dest_ip || 'N/A'}
                </div>
                <div className="col-span-2 text-sm text-slate-400 font-mono">
                  {new Date(alert.timestamp).toLocaleString()}
                </div>
                <div className="col-span-2 text-right">
                  <span className="px-2.5 py-1 bg-slate-800 text-slate-300 text-[10px] rounded-md border border-slate-700 shadow-sm uppercase tracking-wider">
                    {alert.mitre_tactic || 'NONE'}
                  </span>
                </div>
              </div>
            )}
          />
        )}
      </div>
    </div>
  );
};

export default FalsePositivesView;
