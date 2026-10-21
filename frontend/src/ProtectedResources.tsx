import { type FormEvent, useEffect, useState } from 'react';
import { Check, LockKeyhole, Pencil, Plus, Trash2, X } from 'lucide-react';
import { apiRequest } from './services/api';

type Classification = 'WORKING' | 'SENSITIVE' | 'PRIVATE' | 'CRITICAL' | 'UNKNOWN';
type Decision = 'MONITOR' | 'APPROVAL' | 'BLOCK';
type ProtectedResource = {
  id: string;
  path: string;
  classification: Classification;
  decision: Decision;
  enabled: boolean;
  description: string;
  created_at: string | null;
  updated_at: string | null;
};
type FormState = { path: string; classification: Classification; decision: Decision; description: string; enabled: boolean };
const blank: FormState = { path: '', classification: 'SENSITIVE', decision: 'APPROVAL', description: '', enabled: true };
const classifications: Classification[] = ['WORKING', 'SENSITIVE', 'PRIVATE', 'CRITICAL', 'UNKNOWN'];
const decisions: Decision[] = ['MONITOR', 'APPROVAL', 'BLOCK'];

function Tag({ value }: { value: string }) {
  return <span className={`badge ${value.toLowerCase()}`}><i />{value}</span>;
}

function formatDate(value: string | null) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

export default function ProtectedResources() {
  const [items, setItems] = useState<ProtectedResource[]>([]);
  const [editing, setEditing] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<FormState>(blank);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function refresh() {
    try {
      setItems(await apiRequest<ProtectedResource[]>('/protected-resources'));
      setError('');
    } catch (e: any) {
      setError(e.message || 'Could not load protected resources.');
    }
  }

  useEffect(() => { void refresh(); }, []);

  function startCreate() {
    setEditing(null);
    setForm(blank);
    setShowForm(true);
  }

  function startEdit(item: ProtectedResource) {
    setEditing(item.id);
    setForm({ path: item.path, classification: item.classification, decision: item.decision, description: item.description, enabled: item.enabled });
    setShowForm(true);
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const path = editing ? `/protected-resources/${editing}` : '/protected-resources';
      await apiRequest(path, { method: editing ? 'PUT' : 'POST', body: JSON.stringify(form) });
      setShowForm(false);
      setEditing(null);
      await refresh();
    } catch (e: any) {
      setError(e.message || 'Could not save protected resource.');
    } finally {
      setBusy(false);
    }
  }

  async function remove(item: ProtectedResource) {
    try {
      await apiRequest(`/protected-resources/${item.id}`, { method: 'DELETE' });
      await refresh();
    } catch (e: any) {
      setError(e.message || 'Could not delete protected resource.');
    }
  }

  return <>
    <div className="protected-toolbar">
      <div><span className="tiny-tag">CONTROLLED WORKSPACE</span><p>Set explicit classifications and decisions for paths and patterns.</p></div>
      <button className="primary" onClick={startCreate}><Plus size={15} /> Protect resource</button>
    </div>
    {error && <div className="error">{error}</div>}
    {showForm && <form className="panel protected-form" onSubmit={save}>
      <div className="panel-title"><div><h2>{editing ? 'Edit protected resource' : 'Protect a resource'}</h2><p>Use a path relative to controlled_workspace, or an absolute path inside it. * and ? patterns are supported.</p></div></div>
      <div className="protected-fields">
        <label>Resource path<input required maxLength={2000} value={form.path} onChange={e => setForm({ ...form, path: e.target.value })} placeholder="secrets/*" /></label>
        <label>Classification<select value={form.classification} onChange={e => setForm({ ...form, classification: e.target.value as Classification })}>{classifications.map(value => <option key={value}>{value}</option>)}</select></label>
        <label>Policy<select value={form.decision} onChange={e => setForm({ ...form, decision: e.target.value as Decision })}>{decisions.map(value => <option key={value}>{value}</option>)}</select></label>
        <label className="protected-description">Description<input maxLength={1000} value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Why this resource is protected" /></label>
        <label className="protected-enabled"><input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} /> Enabled</label>
      </div>
      <div className="protected-form-actions"><button type="submit" className="approve" disabled={busy}><Check size={14} /> Save</button><button type="button" className="secondary" onClick={() => { setShowForm(false); setEditing(null); }}><X size={14} /> Cancel</button></div>
    </form>}
    <section className="panel table-panel protected-table">
      <div className="panel-title table-heading"><div><h2>Protected resources</h2><p>{items.length} configured path{items.length === 1 ? '' : 's'}</p></div></div>
      <div className="overflow"><table><thead><tr><th>PATH</th><th>CLASSIFICATION</th><th>POLICY</th><th>STATUS</th><th>DESCRIPTION</th><th>CREATED</th><th>ACTIONS</th></tr></thead><tbody>
        {items.map(item => <tr key={item.id}><td><code title={item.path}>{item.path}</code></td><td><Tag value={item.classification} /></td><td><Tag value={item.decision} /></td><td><Tag value={item.enabled ? 'ENABLED' : 'DISABLED'} /></td><td className="protected-description-cell">{item.description || '—'}</td><td>{formatDate(item.created_at)}</td><td><div className="protected-row-actions"><button className="icon-btn" title="Edit" aria-label="Edit protected resource" onClick={() => startEdit(item)}><Pencil size={14} /></button><button className="icon-btn protected-delete" title="Delete" aria-label="Delete protected resource" onClick={() => void remove(item)}><Trash2 size={14} /></button></div></td></tr>)}
      </tbody></table>{items.length === 0 && <div className="empty"><div><LockKeyhole size={23} /></div><b>No protected resources yet</b><span>Add a path or pattern to give it an explicit classification and policy.</span></div>}</div>
    </section>
  </>;
}
