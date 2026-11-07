import { useState, useEffect } from 'react'
import './App.css'

function App() {
  const [file, setFile] = useState(null)
  const [architecture, setArchitecture] = useState('x86')
  const [mode, setMode] = useState('32')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState('')
  const [error, setError] = useState('')

  // Vtable management state
  const [vtables, setVtables] = useState([])
  const [vtLoading, setVtLoading] = useState(false)
  const [vtError, setVtError] = useState('')
  const [showVtableForm, setShowVtableForm] = useState(false)
  const [newVtable, setNewVtable] = useState({
    address: '',
    name: '',
    entries: [{ index: 0, address: '', name: '' }]
  })

  const API_BASE = 'http://localhost:8000'

  // Fetch vtables on load
  useEffect(() => {
    fetchVtables()
  }, [])

  const fetchVtables = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/vtables`)
      const data = await response.json()
      setVtables(data.vtables || [])
    } catch (err) {
      console.error('Failed to fetch vtables:', err)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!file) {
      setError('Please select a binary file')
      return
    }

    setLoading(true)
    setError('')
    setResult('')

    const formData = new FormData()
    formData.append('file', file)
    formData.append('architecture', architecture)
    formData.append('mode', mode)

    try {
      const response = await fetch(`${API_BASE}/api/decompile`, {
        method: 'POST',
        body: formData,
      })

      const data = await response.json()
      if (data.success) {
        setResult(data.output)
      } else {
        setError(data.error || 'Decompilation failed')
      }
    } catch (err) {
      setError(`Request failed: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  const handleAddVtable = async (e) => {
    e.preventDefault()
    setVtLoading(true)
    setVtError('')

    // Validate entries
    const validEntries = newVtable.entries
      .filter(e => e.address && e.index !== '')
      .map(e => ({
        index: parseInt(e.index, 10),
        address: parseInt(e.address.startsWith('0x') ? e.address : '0x' + e.address, 16),
        name: e.name || undefined
      }))

    if (validEntries.length === 0) {
      setVtError('At least one valid entry required')
      setVtLoading(false)
      return
    }

    try {
      const response = await fetch(`${API_BASE}/api/vtables`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: parseInt(newVtable.address.startsWith('0x') ? newVtable.address : '0x' + newVtable.address, 16),
          name: newVtable.name || undefined,
          entries: validEntries
        })
      })

      const data = await response.json()
      if (data.success) {
        setShowVtableForm(false)
        setNewVtable({ address: '', name: '', entries: [{ index: 0, address: '', name: '' }] })
        fetchVtables()
      } else {
        setVtError(data.detail || 'Failed to register vtable')
      }
    } catch (err) {
      setVtError(`Request failed: ${err.message}`)
    } finally {
      setVtLoading(false)
    }
  }

  const handleDeleteVtable = async (address) => {
    if (!confirm(`Delete vtable at 0x${address.toString(16)}?`)) return

    try {
      const response = await fetch(`${API_BASE}/api/vtables/${address}`, {
        method: 'DELETE'
      })
      if (response.ok) {
        fetchVtables()
      }
    } catch (err) {
      console.error('Failed to delete vtable:', err)
    }
  }

  const addEntry = () => {
    const maxIndex = Math.max(...newVtable.entries.map(e => parseInt(e.index, 10) || 0), 0)
    setNewVtable({
      ...newVtable,
      entries: [...newVtable.entries, { index: maxIndex + 1, address: '', name: '' }]
    })
  }

  const removeEntry = (idx) => {
    if (newVtable.entries.length <= 1) return
    setNewVtable({
      ...newVtable,
      entries: newVtable.entries.filter((_, i) => i !== idx)
    })
  }

  const updateEntry = (idx, field, value) => {
    setNewVtable({
      ...newVtable,
      entries: newVtable.entries.map((e, i) => i === idx ? { ...e, [field]: value } : e)
    })
  }

  const updateVtableField = (field, value) => {
    setNewVtable({ ...newVtable, [field]: value })
  }

  return (
    <div className="app">
      <header>
        <h1>cobalt-hub-145 Decompiler</h1>
      </header>
      <main>
        <form onSubmit={handleSubmit} className="decompile-form">
          <div className="form-group">
            <label htmlFor="binary-file">Binary File</label>
            <input
              id="binary-file"
              type="file"
              accept=".bin,.exe,.dll,.so,.o,.elf"
              onChange={(e) => setFile(e.target.files[0])}
              disabled={loading}
            />
            {file && <span className="file-name">{file.name} ({file.size} bytes)</span>}
          </div>

          <div className="form-row">
            <div className="form-group">
              <label htmlFor="architecture">Architecture</label>
              <select
                id="architecture"
                value={architecture}
                onChange={(e) => setArchitecture(e.target.value)}
                disabled={loading}
              >
                <option value="x86">x86</option>
                <option value="arm">ARM</option>
                <option value="mips">MIPS</option>
              </select>
            </div>
            <div className="form-group">
              <label htmlFor="mode">Mode</label>
              <select
                id="mode"
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                disabled={loading}
              >
                <option value="16">16-bit</option>
                <option value="32">32-bit</option>
                <option value="64">64-bit</option>
              </select>
            </div>
          </div>

          <button type="submit" disabled={loading || !file}>
            {loading ? 'Decompiling...' : 'Decompile'}
          </button>

          {error && <div className="error">{error}</div>}
        </form>

        {result && (
          <div className="result-section">
            <h2>Decompilation Output</h2>
            <pre className="result-output">{result}</pre>
          </div>
        )}

        {/* Vtable Management Section */}
        <section className="vtable-section">
          <div className="section-header">
            <h2>Vtable Analysis</h2>
            <button 
              type="button" 
              className="toggle-btn"
              onClick={() => setShowVtableForm(!showVtableForm)}
            >
              {showVtableForm ? 'Hide' : 'Register'} Vtable
            </button>
          </div>

          {showVtableForm && (
            <form onSubmit={handleAddVtable} className="vtable-form">
              <div className="form-group">
                <label>Vtable Address</label>
                <input
                  type="text"
                  placeholder="0x3000"
                  value={newVtable.address}
                  onChange={(e) => updateVtableField('address', e.target.value)}
                  required
                />
              </div>
              <div className="form-group">
                <label>Vtable Name (optional)</label>
                <input
                  type="text"
                  placeholder="MyClass_vtable"
                  value={newVtable.name}
                  onChange={(e) => updateVtableField('name', e.target.value)}
                />
              </div>
              
              <h3>Entries</h3>
              {newVtable.entries.map((entry, idx) => (
                <div key={idx} className="vtable-entry-row">
                  <div className="form-group small">
                    <label>Index</label>
                    <input
                      type="number"
                      min="0"
                      value={entry.index}
                      onChange={(e) => updateEntry(idx, 'index', e.target.value)}
                    />
                  </div>
                  <div className="form-group">
                    <label>Function Address</label>
                    <input
                      type="text"
                      placeholder="0x1000"
                      value={entry.address}
                      onChange={(e) => updateEntry(idx, 'address', e.target.value)}
                    />
                  </div>
                  <div className="form-group">
                    <label>Function Name (optional)</label>
                    <input
                      type="text"
                      placeholder="MyClass::func1"
                      value={entry.name}
                      onChange={(e) => updateEntry(idx, 'name', e.target.value)}
                    />
                  </div>
                  {newVtable.entries.length > 1 && (
                    <button 
                      type="button" 
                      className="remove-btn"
                      onClick={() => removeEntry(idx)}
                    >
                      Remove
                    </button>
                  )}
                </div>
              ))}
              <button type="button" className="add-btn" onClick={addEntry}>
                Add Entry
              </button>

              <button type="submit" disabled={vtLoading} className="primary-btn">
                {vtLoading ? 'Registering...' : 'Register Vtable'}
              </button>
              <button 
                type="button" 
                className="secondary-btn"
                onClick={() => setShowVtableForm(false)}
              >
                Cancel
              </button>
              {vtError && <div className="error">{vtError}</div>}
            </form>
          )}

          <div className="vtables-list">
            <h3>Registered Vtables ({vtables.length})</h3>
            {vtables.length === 0 ? (
              <p className="empty">No vtables registered. Click "Register Vtable" to add one.</p>
            ) : (
              <ul>
                {vtables.map(vt => (
                  <li key={vt.address} className="vtable-item">
                    <div className="vtable-header">
                      <strong>{vt.name || `vtable_0x${vt.address.toString(16)}`}</strong>
                      <span className="vtable-address">0x{vt.address.toString(16)}</span>
                      <button 
                        className="delete-btn"
                        onClick={() => handleDeleteVtable(vt.address)}
                      >
                        Delete
                      </button>
                    </div>
                    <table className="vtable-entries-table">
                      <thead>
                        <tr>
                          <th>Index</th>
                          <th>Address</th>
                          <th>Name</th>
                        </tr>
                      </thead>
                      <tbody>
                        {vt.entries.map(entry => (
                          <tr key={entry.index}>
                            <td>{entry.index}</td>
                            <td>0x{entry.address.toString(16)}</td>
                            <td>{entry.name || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      </main>
    </div>
  )
}

export default App
