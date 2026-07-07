import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { Activity, Search, Info } from 'lucide-react';
import AlertsView from './components/views/AlertsView';
import DeepDiveView from './components/views/DeepDiveView';
import BenignAlertsView from './components/views/BenignAlertsView';
import clsx from 'clsx';

function NavLinks() {
  const location = useLocation();
  return (
    <>
      <Link to="/" className={clsx("p-3 rounded-xl transition-all duration-300", location.pathname === '/' ? "bg-slate-700 shadow-lg shadow-sky-500/20" : "hover:bg-slate-700/50")} title="Grouped Alerts">
        <Activity size={24} className="text-sky-400" />
      </Link>
      <Link to="/benign" className={clsx("p-3 rounded-xl transition-all duration-300", location.pathname === '/benign' ? "bg-slate-700 shadow-lg shadow-blue-500/20" : "hover:bg-slate-700/50")} title="Benign Alerts">
        <Info size={24} className="text-blue-400" />
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
            <Route path="/benign" element={<BenignAlertsView />} />
            <Route path="/deep-dive" element={<DeepDiveView />} />
            <Route path="/deep-dive/:id" element={<DeepDiveView />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
