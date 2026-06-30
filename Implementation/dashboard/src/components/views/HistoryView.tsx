import { useEffect, useState } from 'react';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';

const HistoryView = () => {
  const [metrics, setMetrics] = useState<any>(null);

  useEffect(() => {
    fetch('http://localhost:8000/api/v1/metrics/historical')
      .then(res => res.json())
      .then(data => setMetrics(data))
      .catch(console.error);
  }, []);

  if (!metrics) return <div className="p-10 text-slate-400">Loading metrics...</div>;

  return (
    <div className="p-8 h-full overflow-auto bg-slate-900">
      <h1 className="text-3xl font-bold mb-8 text-slate-100 tracking-tight">Phase 12 Metrics</h1>
      
      {/* KPI Cards */}
      <div className="grid grid-cols-3 gap-6 mb-8">
        <div className="bg-slate-800 border border-slate-700 p-6 rounded-xl shadow-lg shadow-black/20">
          <h3 className="text-slate-400 text-sm font-semibold uppercase tracking-wider mb-2">Workload Reduction</h3>
          <p className="text-4xl font-light text-emerald-400">{metrics.workload_reduction}%</p>
        </div>
        <div className="bg-slate-800 border border-slate-700 p-6 rounded-xl shadow-lg shadow-black/20">
          <h3 className="text-slate-400 text-sm font-semibold uppercase tracking-wider mb-2">False Positive Reduction</h3>
          <p className="text-4xl font-light text-emerald-400">{metrics.false_positive_reduction}%</p>
        </div>
        <div className="bg-slate-800 border border-slate-700 p-6 rounded-xl shadow-lg shadow-black/20">
          <h3 className="text-slate-400 text-sm font-semibold uppercase tracking-wider mb-2">Mean Time To Triage (MTTT)</h3>
          <p className="text-4xl font-light text-sky-400">{metrics.mttt}</p>
        </div>
      </div>

      {/* Main Charts */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        <div className="bg-slate-800 border border-slate-700 p-6 rounded-xl shadow-lg">
          <h3 className="text-lg font-semibold text-slate-200 mb-6">Alert Compression (Raw vs Correlated)</h3>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={metrics.chart_data}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                <XAxis dataKey="time" stroke="#94a3b8" />
                <YAxis yAxisId="left" stroke="#94a3b8" />
                <YAxis yAxisId="right" orientation="right" stroke="#94a3b8" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f1f5f9' }}
                  itemStyle={{ color: '#f1f5f9' }}
                />
                <Legend />
                <Line yAxisId="left" type="monotone" dataKey="raw_alerts" stroke="#ef4444" strokeWidth={2} dot={false} name="Raw Alerts" />
                <Line yAxisId="right" type="monotone" dataKey="correlated" stroke="#10b981" strokeWidth={3} name="Correlated Investigations" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-slate-800 border border-slate-700 p-6 rounded-xl shadow-lg">
          <h3 className="text-lg font-semibold text-slate-200 mb-6">Top MITRE Tactics</h3>
          <div className="h-[300px] flex items-center justify-center text-slate-500 border-2 border-dashed border-slate-700 rounded-lg">
             {/* Placeholder for MITRE Heatmap / Bar chart */}
             <p>MITRE Heatmap Visualization Pending</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HistoryView;
