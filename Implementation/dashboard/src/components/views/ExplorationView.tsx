import { useState } from 'react';
import { AgGridReact } from 'ag-grid-react';
import type { ColDef } from 'ag-grid-community';
import 'ag-grid-community/styles/ag-grid.css';
import 'ag-grid-community/styles/ag-theme-alpine.css';

const ExplorationView = () => {
  const [rowData, setRowData] = useState<any[]>([]);
  const [query, setQuery] = useState('');

  const [columnDefs] = useState<ColDef<any>[]>([
    { field: 'investigation_id', headerName: 'ID', flex: 1 },
    { field: 'status', flex: 1 },
    { field: 'rule_name', flex: 2 },
    { field: 'created_at', flex: 1 }
  ]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetch('http://localhost:8000/api/v1/investigations/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    })
      .then(res => res.json())
      .then(data => setRowData(data))
      .catch(console.error);
  };

  return (
    <div className="flex flex-col h-full bg-slate-900 p-8">
      <h1 className="text-3xl font-bold mb-6 text-slate-100 tracking-tight">Threat Hunting</h1>
      
      {/* Search Bar */}
      <form onSubmit={handleSearch} className="mb-6 flex gap-4">
        <input 
          type="text" 
          placeholder="KQL Query (e.g. src_ip: 192.168.1.50 AND priority > 80)"
          className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-4 py-3 text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500 font-mono text-sm"
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
        <button type="submit" className="px-6 py-3 bg-sky-600 hover:bg-sky-500 text-white rounded-lg font-medium transition-colors">
          Search
        </button>
      </form>

      {/* AG Grid */}
      <div className="flex-1 ag-theme-alpine-dark w-full border border-slate-700 rounded-lg overflow-hidden">
        <AgGridReact
          rowData={rowData}
          columnDefs={columnDefs}
          rowSelection="multiple"
          animateRows={true}
          defaultColDef={{
            sortable: true,
            filter: true,
            resizable: true,
          }}
        />
      </div>
    </div>
  );
};

export default ExplorationView;
