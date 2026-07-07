import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { Activity, ShieldOff, Search } from 'lucide-react';
import AlertsView from './components/views/AlertsView';
import FalsePositivesView from './components/views/FalsePositivesView';
import DeepDiveView from './components/views/DeepDiveView';
import clsx from 'clsx';

function NavLinks() {
  const location = useLocation();
  return (
    <>
      <Link to="/" className={clsx("p-3 rounded-xl transition-all duration-300", location.pathname === '/' ? "bg-slate-700 shadow-lg shadow-sky-500/20" : "hover:bg-slate-700/50")} title="Alerts">
        <Activity size={24} className="text-sky-400" />
      </Link>
      <Link to="/false-positives" className={clsx("p-3 rounded-xl transition-all duration-300", location.pathname === '/false-positives' ? "bg-slate-700 shadow-lg shadow-rose-500/20" : "hover:bg-slate-700/50")} title="False Positives">
        <ShieldOff size={24} className="text-rose-400" />
      </Link>
      <Link to="/deep-dive" className={clsx("p-3 rounded-xl transition-all duration-300", location.pathname.startsWith('/deep-dive') ? "bg-slate-700 shadow-lg shadow-emerald-500/20" : "hover:bg-slate-700/50")} title="Deep Dive">
        <Search size={24} className="text-emerald-400" />
      </Link>
    </>
  );
}

function App() {
  return (
    <Router>
      <div className="flex h-screen bg-slate-900 text-slate-100 font-sans overflow-hidden">
        {/* Sidebar Nav */}
        <nav className="w-16 flex flex-col items-center py-6 bg-slate-800/80 backdrop-blur border-r border-slate-700 gap-8 z-50">
          <NavLinks />
        </nav>
        
        {/* Main Content */}
        <main className="flex-1 relative h-full bg-slate-900/50 overflow-y-auto">
          <Routes>
            <Route path="/" element={<AlertsView />} />
            <Route path="/false-positives" element={<FalsePositivesView />} />
            <Route path="/deep-dive" element={<DeepDiveView />} />
            <Route path="/deep-dive/:id" element={<DeepDiveView />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
