import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { Activity, History, Search, Settings } from 'lucide-react';
import LiveView from './components/views/LiveView';
import HistoryView from './components/views/HistoryView';
import ExplorationView from './components/views/ExplorationView';
import SimulationControl from './components/views/SimulationControl';

function App() {
  return (
    <Router>
      <div className="flex h-screen bg-slate-900 text-slate-100 font-sans overflow-hidden">
        {/* Sidebar Nav */}
        <nav className="w-16 flex flex-col items-center py-6 bg-slate-800 border-r border-slate-700 gap-8">
          <Link to="/" className="p-3 rounded-xl hover:bg-slate-700 transition-colors" title="Live Triage">
            <Activity size={24} className="text-sky-400" />
          </Link>
          <Link to="/history" className="p-3 rounded-xl hover:bg-slate-700 transition-colors" title="Metrics & History">
            <History size={24} className="text-indigo-400" />
          </Link>
          <Link to="/explore" className="p-3 rounded-xl hover:bg-slate-700 transition-colors" title="Threat Hunting">
            <Search size={24} className="text-emerald-400" />
          </Link>
          <div className="flex-grow"></div>
          <Link to="/admin" className="p-3 rounded-xl hover:bg-slate-700 transition-colors" title="Engine Controls">
            <Settings size={24} className="text-slate-400" />
          </Link>
        </nav>
        
        {/* Main Content */}
        <main className="flex-1 relative h-full">
          <Routes>
            <Route path="/" element={<LiveView />} />
            <Route path="/history" element={<HistoryView />} />
            <Route path="/explore" element={<ExplorationView />} />
            <Route path="/admin" element={<SimulationControl />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
