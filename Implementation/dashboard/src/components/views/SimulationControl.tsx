import { useState } from 'react';
import Editor from '@monaco-editor/react';
import { Play, Square, Pause } from 'lucide-react';

const SimulationControl = () => {
  const [rules, setRules] = useState('{\n  "asset_criticality_multiplier": 1.5\n}');

  const handleSave = () => {
    try {
      const parsed = JSON.parse(rules);
      fetch('http://localhost:8000/api/v1/config/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules: parsed })
      })
      .then(() => alert("Rules updated and engine hot-reloaded!"))
      .catch(console.error);
    } catch (e) {
      alert("Invalid JSON format");
    }
  };

  const handleSimulationCommand = (command: string) => {
    fetch('http://localhost:8000/api/v1/simulation/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command, speed: 10 })
    }).catch(console.error);
  };

  return (
    <div className="flex h-full bg-slate-900">
      {/* Left Panel - Controls */}
      <div className="w-1/3 border-r border-slate-700 p-8 flex flex-col">
        <h1 className="text-3xl font-bold mb-8 text-slate-100 tracking-tight">Lab Controls</h1>
        
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 mb-8">
          <h2 className="text-lg font-semibold text-slate-200 mb-4">Replay Engine</h2>
          <div className="flex gap-4">
            <button onClick={() => handleSimulationCommand('START')} className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-medium transition-colors">
              <Play size={18} /> Play
            </button>
            <button onClick={() => handleSimulationCommand('PAUSE')} className="flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded font-medium transition-colors">
              <Pause size={18} /> Pause
            </button>
            <button onClick={() => handleSimulationCommand('STOP')} className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded font-medium transition-colors">
              <Square size={18} /> Stop
            </button>
          </div>
          <div className="mt-6">
            <label className="block text-sm font-medium text-slate-400 mb-2">Speed Multiplier</label>
            <select className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-slate-200">
              <option value="1">1x (Real-time)</option>
              <option value="10">10x (Accelerated)</option>
              <option value="100">100x (Max Throughput)</option>
            </select>
          </div>
        </div>

        {/* A/B Comparison Preview */}
        <div className="flex-1 bg-slate-800 p-6 rounded-xl border border-slate-700 flex flex-col">
          <h2 className="text-lg font-semibold text-slate-200 mb-4">A/B Split Simulation</h2>
          <div className="flex-1 flex gap-4">
            <div className="flex-1 bg-slate-900 rounded border border-slate-700 p-4 flex flex-col items-center justify-center text-center">
              <span className="text-sm text-slate-500 mb-2">Baseline (Raw Alerts)</span>
              <span className="text-3xl font-mono text-red-500 animate-pulse">4,205</span>
            </div>
            <div className="flex-1 bg-slate-900 rounded border border-slate-700 p-4 flex flex-col items-center justify-center text-center">
              <span className="text-sm text-slate-500 mb-2">Enhanced (Context-Aware)</span>
              <span className="text-3xl font-mono text-emerald-500">32</span>
            </div>
          </div>
        </div>
      </div>

      {/* Right Panel - Rules Editor */}
      <div className="w-2/3 flex flex-col">
        <div className="p-4 bg-slate-800 border-b border-slate-700 flex justify-between items-center">
          <h2 className="text-lg font-semibold text-slate-200">Rules & Thresholds Engine (rules.json)</h2>
          <button onClick={handleSave} className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded font-medium transition-colors text-sm">
            Save & Hot Reload
          </button>
        </div>
        <div className="flex-1">
          <Editor
            height="100%"
            defaultLanguage="json"
            theme="vs-dark"
            value={rules}
            onChange={(val) => setRules(val || '')}
            options={{
              minimap: { enabled: false },
              fontSize: 14,
              fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
            }}
          />
        </div>
      </div>
    </div>
  );
};

export default SimulationControl;
