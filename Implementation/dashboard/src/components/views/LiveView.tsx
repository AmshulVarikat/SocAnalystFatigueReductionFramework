import { useState } from 'react';
import { Virtuoso } from 'react-virtuoso';
import { useInvestigationQueue } from '../../store/zustandAdapter';
import { useSocketBridge } from '../../hooks/useSocketBridge';
import InvestigationDrawer from './InvestigationDrawer';
import type { Investigation } from '../../types';
import clsx from 'clsx';

const getSeverityColor = (priority: number) => {
  if (priority >= 90) return 'bg-[var(--color-severity-critical)] text-white';
  if (priority >= 60) return 'bg-[var(--color-severity-investigate)] text-white';
  if (priority >= 30) return 'bg-[var(--color-severity-fp)] text-slate-900';
  return 'bg-[var(--color-severity-benign)] text-white';
};

const LiveView = () => {
  const { queue, health } = useInvestigationQueue();
  const { sendCommand } = useSocketBridge('ws://localhost:8000/ws');
  const [selectedInvId, setSelectedInvId] = useState<string | null>(null);

  const handleRowClick = (inv: Investigation) => {
    setSelectedInvId(inv.investigation_id);
  };

  return (
    <div className="flex flex-col h-full bg-slate-900">
      {/* Header */}
      <header className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-800/50 backdrop-blur">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight">Active Investigations</h1>
          <p className="text-slate-400 text-sm mt-1">Real-time triage queue driven by Context-Aware Engine</p>
        </div>
        
        <div className="flex gap-6 items-center">
          <div className="flex flex-col items-end">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Events / Sec</span>
            <span className="text-xl font-mono text-emerald-400">{health.eps.toLocaleString()}</span>
          </div>
          <div className="flex flex-col items-end">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Active Queue</span>
            <span className="text-xl font-mono text-sky-400">{queue.length}</span>
          </div>
        </div>
      </header>

      {/* Queue Table Header */}
      <div className="grid grid-cols-12 gap-4 px-6 py-3 border-b border-slate-800 text-xs font-semibold text-slate-400 uppercase tracking-wider bg-slate-800/30">
        <div className="col-span-2">Priority</div>
        <div className="col-span-4">Rule Name</div>
        <div className="col-span-2">Created At</div>
        <div className="col-span-2">Status</div>
        <div className="col-span-2 text-right">Actions</div>
      </div>

      {/* Virtualized List */}
      <div className="flex-1 overflow-hidden relative">
        {queue.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center text-slate-500 flex-col gap-2">
            <div className="w-16 h-16 rounded-full bg-slate-800 flex items-center justify-center animate-pulse">
              <span className="block w-6 h-6 border-2 border-slate-600 rounded-full border-t-emerald-500 animate-spin"></span>
            </div>
            <p>Waiting for engine events...</p>
          </div>
        ) : (
          <Virtuoso
            style={{ height: '100%' }}
            data={queue}
            itemContent={(_, inv) => (
              <div 
                onClick={() => handleRowClick(inv)}
                className="grid grid-cols-12 gap-4 px-6 py-4 border-b border-slate-800/50 hover:bg-slate-800/80 cursor-pointer transition-colors group items-center"
              >
                <div className="col-span-2 flex items-center gap-3">
                  <div className={clsx("px-2 py-1 rounded text-xs font-bold font-mono", getSeverityColor(inv.current_priority))}>
                    {inv.current_priority.toFixed(1)}
                  </div>
                </div>
                <div className="col-span-4 text-sm font-medium text-slate-200 truncate pr-4">
                  {inv.rule_name}
                </div>
                <div className="col-span-2 text-sm text-slate-400 font-mono">
                  {new Date(inv.created_at).toLocaleTimeString()}
                </div>
                <div className="col-span-2">
                  <span className="px-2 py-1 bg-slate-800 text-slate-300 text-xs rounded-full border border-slate-700">
                    {inv.status}
                  </span>
                </div>
                <div className="col-span-2 flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button 
                    onClick={(e) => { e.stopPropagation(); sendCommand('UPDATE_INVESTIGATION_STATUS', { id: inv.investigation_id, action: 'ACKNOWLEDGE' })}}
                    className="px-3 py-1 bg-sky-500/10 text-sky-400 hover:bg-sky-500/20 rounded text-xs transition-colors border border-sky-500/20"
                  >
                    ACK
                  </button>
                  <button 
                    onClick={(e) => { e.stopPropagation(); sendCommand('UPDATE_INVESTIGATION_STATUS', { id: inv.investigation_id, action: 'RESOLVE' })}}
                    className="px-3 py-1 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 rounded text-xs transition-colors border border-emerald-500/20"
                  >
                    RESOLVE
                  </button>
                </div>
              </div>
            )}
          />
        )}
      </div>

      {/* Sliding Drawer */}
      <InvestigationDrawer 
        investigationId={selectedInvId} 
        onClose={() => setSelectedInvId(null)} 
      />
    </div>
  );
};

export default LiveView;
