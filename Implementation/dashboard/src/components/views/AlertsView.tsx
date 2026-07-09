import { useState, useEffect } from 'react';
import { Virtuoso } from 'react-virtuoso';
import { useNavigate } from 'react-router-dom';
import clsx from 'clsx';
import { ShieldCheck, ShieldAlert, CheckCircle, Search } from 'lucide-react';

interface UnifiedAlert {
  id: string;
  type: 'investigation' | 'alert';
  priority: number;
  rule_name: string;
  created_at: string;
  status: string;
}

const getSeverityColor = (priority: number) => {
  if (priority >= 90) return 'bg-rose-500/20 text-rose-400 border-rose-500/30';
  if (priority >= 60) return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
  if (priority >= 30) return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
  return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
};

const AlertsView = () => {
  const [alerts, setAlerts] = useState<UnifiedAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const fetchAlerts = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/v1/alerts');
      const data = await res.json();
      setAlerts(data.sort((a: UnifiedAlert, b: UnifiedAlert) => b.priority - a.priority));
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    // In a real app, we'd hook up websockets here to update the list live.
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleAck = async (id: string, type: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (type === 'investigation') {
      try {
        await fetch(`http://localhost:8000/api/v1/investigations/${id}/ack`, { method: 'POST' });
      } catch (err) {
        console.error(err);
      }
    }
    // Optimistic UI update
    setAlerts(alerts.filter(a => a.id !== id));
  };

  const handleResolve = (id: string, type: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (type === 'investigation') {
      navigate(`/deep-dive/${id}`);
    } else {
      // If it's just a benign alert, remove it or do nothing
      setAlerts(alerts.filter(a => a.id !== id));
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <header className="p-8 border-b border-slate-800/60 bg-slate-900/40 backdrop-blur-md sticky top-0 z-10">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-sky-500/10 rounded-2xl border border-sky-500/20">
            <ShieldAlert className="text-sky-400" size={28} />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-slate-100 to-slate-400 tracking-tight">Grouped Investigations</h1>
            <p className="text-slate-400 text-sm mt-2 font-medium">Correlated multi-alert investigations</p>
          </div>
        </div>
      </header>

      {/* Queue Table Header */}
      <div className="grid grid-cols-12 gap-6 px-8 py-4 border-b border-slate-800/60 text-xs font-bold text-slate-500 uppercase tracking-widest bg-slate-900/80 sticky top-[105px] z-10 backdrop-blur-md">
        <div className="col-span-2">Risk/Priority</div>
        <div className="col-span-1">Type</div>
        <div className="col-span-4">Rule / Context</div>
        <div className="col-span-2">Detected At</div>
        <div className="col-span-1">Status</div>
        <div className="col-span-2 text-right">Quick Actions</div>
      </div>

      {/* Virtualized List */}
      <div className="flex-1 overflow-hidden relative bg-slate-900/20">
        {loading ? (
          <div className="absolute inset-0 flex items-center justify-center text-slate-500 flex-col gap-4">
            <div className="w-12 h-12 rounded-full border-2 border-slate-700 border-t-sky-500 animate-spin"></div>
            <p className="animate-pulse tracking-wide font-medium">Loading alerts...</p>
          </div>
        ) : alerts.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center text-slate-500 flex-col gap-4">
            <ShieldCheck size={48} className="text-emerald-500/50" />
            <p className="tracking-wide font-medium text-lg">No active alerts to triage.</p>
          </div>
        ) : (
          <Virtuoso
            style={{ height: '100%' }}
            data={alerts}
            itemContent={(_, alert) => (
              <div 
                className="grid grid-cols-12 gap-6 px-8 py-5 border-b border-slate-800/40 hover:bg-slate-800/40 transition-all duration-200 group items-center"
              >
                <div className="col-span-2 flex items-center">
                  <div className={clsx("px-3 py-1.5 rounded-lg text-sm font-bold font-mono border shadow-sm", getSeverityColor(alert.priority))}>
                    {alert.priority.toFixed(1)}
                  </div>
                </div>
                <div className="col-span-1">
                  <span className={clsx(
                    "px-2.5 py-1 text-[10px] uppercase font-bold tracking-wider rounded-md border",
                    alert.type === 'investigation' ? "bg-indigo-500/10 text-indigo-400 border-indigo-500/20" : "bg-slate-500/10 text-slate-400 border-slate-500/20"
                  )}>
                    {alert.type}
                  </span>
                </div>
                <div className="col-span-4 text-sm font-semibold text-slate-200 truncate pr-4">
                  {alert.rule_name}
                </div>
                <div className="col-span-2 text-sm text-slate-400 font-mono">
                  {new Date(alert.created_at).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' })}
                </div>
                <div className="col-span-1">
                  <span className="px-2.5 py-1 bg-slate-800 text-slate-300 text-xs rounded-full border border-slate-700 shadow-sm">
                    {alert.status}
                  </span>
                </div>
                <div className="col-span-2 flex justify-end gap-3 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                  <button 
                    onClick={(e) => handleAck(alert.id, alert.type, e)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg text-xs font-semibold transition-all border border-slate-600 hover:border-slate-500 shadow-sm"
                    title="Acknowledge & Remove"
                  >
                    <CheckCircle size={14} />
                    ACK
                  </button>
                  {alert.type === 'investigation' && (
                    <button 
                      onClick={(e) => handleResolve(alert.id, alert.type, e)}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 hover:text-sky-300 rounded-lg text-xs font-semibold transition-all border border-sky-500/30 hover:border-sky-500/50 shadow-sm shadow-sky-500/10"
                      title="Deep Dive Investigation"
                    >
                      <Search size={14} />
                      RESOLVE
                    </button>
                  )}
                </div>
              </div>
            )}
          />
        )}
      </div>
    </div>
  );
};

export default AlertsView;
