
import { useState } from 'react'
import './App.css'

function App() {
  const [file, setFile] = useState(null)
  const [architecture, setArchitecture] = useState('x86')
  const [mode, setMode] = useState('32')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState('')
  const [error, setError] = useState('')

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
      const response = await fetch('http://localhost:8000/api/decompile', {
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
      </main>
    </div>
  )
}

export default App
