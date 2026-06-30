import React, { useEffect, useState } from 'react';
import { ReactFlow, Background, Controls } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { X } from 'lucide-react';
import clsx from 'clsx';

interface DrawerProps {
  investigationId: string | null;
  onClose: () => void;
}

const InvestigationDrawer: React.FC<DrawerProps> = ({ investigationId, onClose }) => {
  const [activeTab, setActiveTab] = useState<'graph' | 'raw'>('graph');
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [alerts, setAlerts] = useState<any[]>([]);

  useEffect(() => {
    if (investigationId) {
      // Fetch Graph Data
      fetch(`http://localhost:8000/api/v1/investigations/${investigationId}/graph`)
        .then(res => res.json())
        .then(data => setGraphData(data))
        .catch(console.error);

      // Fetch Raw Alerts
      fetch(`http://localhost:8000/api/v1/investigations/${investigationId}/alerts`)
        .then(res => res.json())
        .then(data => setAlerts(data))
        .catch(console.error);
    }
  }, [investigationId]);

  return (
    <>
      {/* Backdrop */}
      {investigationId && (
        <div 
          className="fixed inset-0 bg-slate-950/50 backdrop-blur-sm z-40 transition-opacity"
          onClick={onClose}
        />
      )}

      {/* Drawer */}
      <div 
        className={clsx(
          "fixed top-0 right-0 h-full w-[45%] bg-slate-900 border-l border-slate-700 shadow-2xl transform transition-transform duration-300 ease-in-out z-50 flex flex-col",
          investigationId ? "translate-x-0" : "translate-x-full"
        )}
      >
        {/* Header */}
        <div className="flex justify-between items-center p-6 border-b border-slate-800 bg-slate-800/50">
          <div>
            <h2 className="text-xl font-bold text-slate-100 truncate">
              Investigation: {investigationId}
            </h2>
            <div className="flex gap-4 mt-4">
              <button
                className={clsx("pb-2 text-sm font-medium border-b-2 transition-colors", activeTab === 'graph' ? 'border-sky-500 text-sky-400' : 'border-transparent text-slate-400 hover:text-slate-200')}
                onClick={() => setActiveTab('graph')}
              >
                Graph Visualizer
              </button>
              <button
                className={clsx("pb-2 text-sm font-medium border-b-2 transition-colors", activeTab === 'raw' ? 'border-sky-500 text-sky-400' : 'border-transparent text-slate-400 hover:text-slate-200')}
                onClick={() => setActiveTab('raw')}
              >
                Raw Evidence
              </button>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded hover:bg-slate-700 text-slate-400 transition-colors self-start">
            <X size={20} />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto relative bg-slate-950">
          {activeTab === 'graph' && (
            <div className="absolute inset-0">
              <ReactFlow 
                nodes={graphData.nodes} 
                edges={graphData.edges}
                fitView
                colorMode="dark"
              >
                <Background />
                <Controls />
              </ReactFlow>
            </div>
          )}
          
          {activeTab === 'raw' && (
            <div className="p-6 h-full overflow-auto font-mono text-xs text-sky-300">
              <pre>{JSON.stringify(alerts, null, 2)}</pre>
            </div>
          )}
        </div>
      </div>
    </>
  );
};

export default InvestigationDrawer;
