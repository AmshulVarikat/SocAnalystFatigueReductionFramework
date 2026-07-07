import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Search, ChevronRight, ShieldAlert, Cpu } from 'lucide-react';
import clsx from 'clsx';

interface Investigation {
  investigation_id: string;
  status: string;
  created_at: string;
  rule_name: string;
  current_priority: number;
  match_values?: string;
  observed_progression?: string;
  alerts_count?: number;
}

interface AlertPayload {
  rule_id: string;
  timestamp: string;
  src_ip?: string;
  dest_ip?: string;
  hostname?: string;
  username?: string;
  process_name?: string;
  file_hash?: string;
  mitre_tactic?: string;
  risk_score?: number;
  asset_context?: any;
  threat_intel?: any;
}

const getSeverityColor = (priority: number) => {
  if (priority >= 90) return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
  if (priority >= 60) return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
  if (priority >= 30) return 'text-blue-400 border-blue-500/30 bg-blue-500/10';
  return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
};

const DeepDiveView = () => {
  const { id: routeId } = useParams();
  const navigate = useNavigate();
  
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(routeId || null);
  const [alerts, setAlerts] = useState<AlertPayload[]>([]);
  const [loading, setLoading] = useState(true);
  const [alertsLoading, setAlertsLoading] = useState(false);

  useEffect(() => {
    const fetchInvs = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/v1/investigations/all');
        const data = await res.json();
        setInvestigations(data.sort((a: Investigation, b: Investigation) => b.current_priority - a.current_priority));
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    fetchInvs();
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    
    const fetchAlerts = async () => {
      setAlertsLoading(true);
      try {
        const res = await fetch(`http://localhost:8000/api/v1/investigations/${selectedId}/alerts`);
        const data = await res.json();
        setAlerts(data);
      } catch (e) {
        console.error(e);
      } finally {
        setAlertsLoading(false);
      }
    };
    
    fetchAlerts();
    // Update URL without triggering reload
    navigate(`/deep-dive/${selectedId}`, { replace: true });
  }, [selectedId, navigate]);

  return (
    <div className="flex h-full bg-slate-900">
      {/* Sidebar: Investigations List */}
      <div className="w-80 border-r border-slate-800/60 bg-slate-900/40 backdrop-blur-md flex flex-col h-full z-10">
        <div className="p-6 border-b border-slate-800/60">
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Search size={20} className="text-emerald-400" />
            Investigations
          </h2>
          <p className="text-xs text-slate-400 mt-1">Select an investigation to view details</p>
        </div>
        
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {loading ? (
             <div className="text-slate-500 text-center py-8 animate-pulse text-sm">Loading...</div>
          ) : investigations.length === 0 ? (
             <div className="text-slate-500 text-center py-8 text-sm">No investigations found</div>
          ) : (
            investigations.map(inv => (
              <div 
                key={inv.investigation_id}
                onClick={() => setSelectedId(inv.investigation_id)}
                className={clsx(
                  "p-3 rounded-xl cursor-pointer transition-all duration-200 border",
                  selectedId === inv.investigation_id 
                    ? "bg-slate-800 border-slate-600 shadow-lg shadow-slate-900/50" 
                    : "bg-slate-800/30 border-transparent hover:bg-slate-800/60"
                )}
              >
                <div className="flex justify-between items-start mb-2">
                  <span className={clsx("px-2 py-0.5 rounded text-[10px] font-bold border", getSeverityColor(inv.current_priority))}>
                    P {inv.current_priority.toFixed(0)}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">
                    {new Date(inv.created_at).toLocaleTimeString([], { hour: '2-digit', minute:'2-digit' })}
                  </span>
                </div>
                <div className="text-sm font-semibold text-slate-200 line-clamp-2">
                  {inv.rule_name}
                </div>
                <div className="text-[10px] text-slate-400 mt-2 uppercase tracking-wider font-semibold">
                  {inv.status}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Main Content: Alert Details */}
      <div className="flex-1 flex flex-col h-full relative bg-slate-900/20">
        {!selectedId ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500">
            <Search size={64} className="text-slate-800 mb-4" />
            <p className="text-lg font-medium">Select an investigation to view alerts</p>
          </div>
        ) : alertsLoading ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500">
            <div className="w-10 h-10 rounded-full border-2 border-slate-700 border-t-emerald-500 animate-spin mb-4"></div>
            <p className="animate-pulse">Loading alerts...</p>
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto p-8 relative">
             <div className="max-w-4xl mx-auto">
               <div className="mb-8">
                 <h1 className="text-3xl font-bold text-slate-100 mb-2">Investigation Details</h1>
                 <p className="text-slate-400 font-mono text-sm">ID: {selectedId}</p>
               </div>
               
               {(() => {
                 const inv = investigations.find(i => i.investigation_id === selectedId);
                 if (!inv) return null;
                 
                 let matchValues = {};
                 let progression = {};
                 try {
                   if (inv.match_values) matchValues = JSON.parse(inv.match_values);
                   if (inv.observed_progression) progression = JSON.parse(inv.observed_progression);
                 } catch (e) {}

                 const hasMatches = Object.keys(matchValues).length > 0;
                 const hasProgression = Object.keys(progression).length > 0;

                 if (!hasMatches && !hasProgression) return null;

                 return (
                   <div className="mb-8 p-5 bg-slate-800/60 backdrop-blur-sm border border-slate-700/80 rounded-2xl shadow-lg">
                     <h3 className="text-lg font-bold text-slate-200 mb-4 flex items-center gap-2">
                       <Search size={18} className="text-sky-400" />
                       Why were these alerts grouped?
                     </h3>
                     <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                       {hasMatches && (
                         <div>
                           <h4 className="text-xs uppercase tracking-wider text-slate-500 font-bold mb-2">Matched Pivot Criteria</h4>
                           <ul className="space-y-2">
                             {Object.entries(matchValues).map(([k, v]) => (
                               <li key={k} className="text-sm bg-slate-900/50 p-2 rounded-lg border border-slate-700/50">
                                 <span className="text-sky-400 font-mono block mb-1">{k}</span> 
                                 <span className="text-slate-300">{Array.isArray(v) ? v.join(', ') : String(v)}</span>
                               </li>
                             ))}
                           </ul>
                         </div>
                       )}
                       {hasProgression && (
                         <div>
                           <h4 className="text-xs uppercase tracking-wider text-slate-500 font-bold mb-2">Observed Progression</h4>
                           <ul className="space-y-2">
                             {Object.entries(progression).map(([k, v]) => (
                               <li key={k} className="text-sm bg-slate-900/50 p-2 rounded-lg border border-slate-700/50">
                                 <span className="text-emerald-400 font-mono block mb-1">{k}</span> 
                                 <span className="text-slate-300">{Array.isArray(v) ? v.join(' → ') : String(v)}</span>
                               </li>
                             ))}
                           </ul>
                         </div>
                       )}
                     </div>
                   </div>
                 );
               })()}
               
               <div className="space-y-8 relative before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-slate-700 before:to-transparent">
                 {Array.isArray(alerts) && alerts.map((alert, idx) => (
                   <div key={idx} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
                     {/* Timeline Dot */}
                     <div className="flex items-center justify-center w-10 h-10 rounded-full border-4 border-slate-900 bg-emerald-500 shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 shadow-emerald-500/20 z-10">
                       <ShieldAlert size={16} className="text-slate-900" />
                     </div>
                     
                     {/* Card */}
                     <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] p-5 rounded-2xl bg-slate-800/80 backdrop-blur border border-slate-700 shadow-xl transition-all duration-300 hover:shadow-emerald-500/10 hover:border-slate-600">
                        <div className="flex justify-between items-center mb-3 border-b border-slate-700/50 pb-3">
                          <span className="text-xs font-bold text-slate-400 bg-slate-900/50 px-2 py-1 rounded">
                            {new Date(alert.timestamp).toLocaleTimeString()}
                          </span>
                          {alert.risk_score !== undefined && (
                            <span className="text-xs font-bold text-rose-400 bg-rose-400/10 px-2 py-1 rounded-full border border-rose-400/20">
                              Risk: {typeof alert.risk_score === 'number' ? alert.risk_score.toFixed(1) : String(alert.risk_score)}
                            </span>
                          )}
                        </div>
                        
                        <h3 className="text-base font-bold text-slate-200 mb-4">{alert.rule_id}</h3>
                        
                        <div className="grid grid-cols-2 gap-4">
                          {/* Identifiable Information */}
                          {(alert.hostname || alert.username || alert.src_ip || alert.dest_ip || alert.file_hash || alert.process_name) && (
                            <div className="col-span-2 bg-slate-900/50 p-3 rounded-lg border border-slate-700/50">
                               <div className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-2">Identifiable Information</div>
                               <div className="grid grid-cols-2 gap-y-2 gap-x-4">
                                 {alert.hostname && (
                                   <div><span className="text-[10px] text-slate-500 block uppercase">Host</span><span className="font-mono text-xs text-emerald-400">{alert.hostname}</span></div>
                                 )}
                                 {alert.username && (
                                   <div><span className="text-[10px] text-slate-500 block uppercase">User</span><span className="font-mono text-xs text-sky-400">{alert.username}</span></div>
                                 )}
                                 {(alert.src_ip || alert.dest_ip) && (
                                   <div className="col-span-2"><span className="text-[10px] text-slate-500 block uppercase">Network</span>
                                     <div className="font-mono text-xs text-indigo-400 flex items-center gap-1 mt-0.5">
                                        {alert.src_ip || 'Any'} <ChevronRight size={12} className="text-slate-600" /> {alert.dest_ip || 'Any'}
                                     </div>
                                   </div>
                                 )}
                                 {alert.process_name && (
                                   <div className="col-span-2"><span className="text-[10px] text-slate-500 block uppercase">Process</span><span className="font-mono text-xs text-purple-400">{alert.process_name}</span></div>
                                 )}
                                 {alert.file_hash && (
                                   <div className="col-span-2"><span className="text-[10px] text-slate-500 block uppercase">File Hash</span><span className="font-mono text-[10px] text-amber-400 break-all">{alert.file_hash}</span></div>
                                 )}
                               </div>
                            </div>
                          )}
                          
                          {/* Mitre Tactic */}
                          {alert.mitre_tactic && (
                            <div className="col-span-1">
                               <div className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-1">Mitre Tactic</div>
                               <div className="text-sm font-semibold text-slate-300">{alert.mitre_tactic}</div>
                            </div>
                          )}
                          
                          {/* Asset Context */}
                          {alert.asset_context && alert.asset_context.criticality && (
                             <div className="col-span-1">
                               <div className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-1">Asset Criticality</div>
                               <div className="text-sm font-semibold text-slate-300 flex items-center gap-1.5">
                                 <Cpu size={14} className="text-indigo-400" />
                                 Level {alert.asset_context.criticality}
                               </div>
                            </div>
                          )}
                        </div>
                     </div>
                   </div>
                 ))}
               </div>
             </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default DeepDiveView;
