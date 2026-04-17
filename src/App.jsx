import { useState, useRef } from 'react'
import { scanFile } from './utils/scannerEngine'
import { injectionRules } from './scanner/rules/injection'
import { xssRules } from './scanner/rules/xss'
import './App.css'

function App() {
  const [files, setFiles] = useState([])
  const [results, setResults] = useState([])
  const [isScanning, setIsScanning] = useState(false)
  const fileInputRef = useRef(null)
  const folderInputRef = useRef(null)

  const handleFileUpload = (e) => {
    const uploadedFiles = Array.from(e.target.files)
    processFiles(uploadedFiles)
  }

  const processFiles = async (fileList) => {
    setIsScanning(true)
    
    const filtered = fileList.filter(file => {
      const path = file.webkitRelativePath || file.name
      const isHidden = path.split('/').some(part => part.startsWith('.'))
      const isNodeModules = path.includes('node_modules')
      const isDist = path.includes('dist') || path.includes('build')
      const extension = path.split('.').pop().toLowerCase()
      const isSupported = ['js', 'jsx', 'ts', 'tsx'].includes(extension)

      return !isHidden && !isNodeModules && !isDist && isSupported
    })

    setFiles(filtered)

    const scanResults = []
    const allRules = [...injectionRules, ...xssRules] // Combine all rule categories
    
    for (const file of filtered) {
      console.log(`Scanning: ${file.name}...`)
      const result = await scanFile(file, allRules)
      scanResults.push(result)
      
      if (result.issues?.length > 0) {
        console.warn(`Vulnerability found in ${file.name}:`, result.issues)
      }
    }
    
    setResults(scanResults)
    console.log("Full Scan Results:", scanResults)
    setIsScanning(false)
  }

  return (
    <div className="min-h-screen bg-slate-50 font-sans text-slate-900">
      {/* Hidden Inputs */}
      <input 
        type="file" 
        ref={fileInputRef} 
        onChange={handleFileUpload} 
        multiple 
        className="hidden" 
        accept=".js,.jsx,.ts,.tsx,.html"
      />
      <input 
        type="file" 
        ref={folderInputRef} 
        onChange={handleFileUpload} 
        webkitdirectory="true" 
        directory="true" 
        className="hidden" 
      />

      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b border-slate-200 bg-white/80 backdrop-blur-md">
        <div className="container mx-auto flex h-16 items-center justify-between px-4">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-red-600 text-white shadow-sm">
              <span className="font-bold">CG</span>
            </div>
            <h1 className="text-xl font-bold tracking-tight text-slate-900">
              CodeGuard<span className="text-red-600">-JS</span>
            </h1>
          </div>
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600">
            <a href="#" className="hover:text-red-600 transition-colors">Documentation</a>
            <a href="#" className="hover:text-red-600 transition-colors">OWASP Rules</a>
            <a href="#" className="hover:text-red-600 transition-colors">GitHub</a>
          </nav>
          <button className="rounded-full bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 transition-all shadow-sm disabled:opacity-50" disabled={files.length === 0}>
            Export Report (PDF)
          </button>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Hero & Upload Section */}
        <section className="mb-12 text-center">
          <h2 className="mb-4 text-4xl font-extrabold tracking-tight text-slate-900 sm:text-5xl">
            Static Security Analysis for JS
          </h2>
          <p className="mx-auto mb-8 max-w-2xl text-lg text-slate-600">
            Analyze your JavaScript code for OWASP vulnerabilities locally in your browser. 
            No data ever leaves your machine.
          </p>
          
          <div className="mx-auto max-w-xl">
            <div 
              className="group relative flex flex-col items-center justify-center rounded-2xl border-2 border-dashed border-slate-300 bg-white p-12 transition-all hover:border-red-400 hover:bg-red-50/50 cursor-pointer"
              onClick={() => folderInputRef.current.click()}
            >
              <div className="mb-4 rounded-full bg-red-100 p-4 text-red-600 group-hover:scale-110 transition-transform">
                <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" x2="12" y1="3" y2="15"/></svg>
              </div>
              <h3 className="mb-2 text-xl font-semibold text-slate-900">Upload Project Folder</h3>
              <p className="text-sm text-slate-500 mb-6 text-center text-pretty">
                Drag and drop your project here or click to select a folder
              </p>
              <div className="flex gap-3">
                <button 
                  className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 shadow-sm"
                  onClick={(e) => { e.stopPropagation(); fileInputRef.current.click(); }}
                >
                  Select Files
                </button>
                <button 
                  className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 shadow-sm"
                  onClick={(e) => { e.stopPropagation(); folderInputRef.current.click(); }}
                >
                  Select Folder
                </button>
              </div>
            </div>
          </div>
        </section>

        {/* Dashboard / Summary Grid */}
        <section className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: 'Files Found', value: files.length, color: 'text-slate-900' },
            { label: 'Total Issues', value: '0', color: 'text-red-600' },
            { label: 'Critical Risks', value: '0', color: 'text-red-700' },
            { label: 'Security Score', value: files.length > 0 ? 'TBD' : '100%', color: 'text-green-600' }
          ].map((stat, i) => (
            <div key={i} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-sm font-medium text-slate-500">{stat.label}</p>
              <p className={`mt-1 text-3xl font-bold ${stat.color}`}>{stat.value}</p>
            </div>
          ))}
        </section>

        {/* Results Area */}
        <div className="grid gap-8 lg:grid-cols-3">
          {/* File List */}
          <section className="lg:col-span-1">
            <div className="rounded-xl border border-slate-200 bg-white overflow-hidden shadow-sm flex flex-col h-[500px]">
              <div className="border-b border-slate-100 bg-slate-50/50 px-4 py-3 flex justify-between items-center">
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500">Files ({files.length})</h3>
                {files.length > 0 && (
                  <button 
                    onClick={() => setFiles([])}
                    className="text-xs font-semibold text-red-600 hover:text-red-700 transition-colors"
                  >
                    Clear All
                  </button>
                )}
              </div>
              <div className="divide-y divide-slate-100 overflow-y-auto flex-1">
                {files.length === 0 ? (
                  <div className="flex items-center justify-center h-full px-6 text-center italic text-slate-400">
                    <p>No files scanned yet. Upload code to begin analysis.</p>
                  </div>
                ) : (
                  files.map((file, idx) => (
                    <div key={idx} className="group flex items-center justify-between px-4 py-3 hover:bg-slate-50 transition-colors cursor-pointer">
                      <div className="flex flex-col min-w-0 pr-4">
                        <span className="text-sm font-medium text-slate-700 truncate">
                          {file.webkitRelativePath || file.name}
                        </span>
                        <span className="text-xs text-slate-400 uppercase tracking-tighter">
                          {file.name.split('.').pop()}
                        </span>
                      </div>
                      <div className="h-2 w-2 rounded-full bg-slate-200"></div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </section>

          {/* Code Viewer / Issue Detail Mockup */}
          <section className="lg:col-span-2">
            <div className="rounded-xl border border-slate-200 bg-white overflow-hidden shadow-sm h-full flex flex-col min-h-[500px]">
              <div className="border-b border-slate-100 bg-slate-50/50 px-4 py-3 flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-700 italic">No file selected</h3>
                <div className="flex gap-2">
                  <div className="h-3 w-3 rounded-full bg-slate-200"></div>
                  <div className="h-3 w-3 rounded-full bg-slate-200"></div>
                  <div className="h-3 w-3 rounded-full bg-slate-200"></div>
                </div>
              </div>
              <div className="flex-1 bg-slate-900 p-6 font-mono text-sm text-slate-300 overflow-auto">
                <div className="opacity-30">
                  <p className="mb-2">// AST-based code analysis will appear here</p>
                  <p className="mb-2">1  const scan = () =&gt; &#123;</p>
                  <p className="mb-2">2    // Select a file to view findings</p>
                  <p className="mb-2">3  &#125;</p>
                </div>
              </div>
            </div>
          </section>
        </div>
      </main>

      {/* Footer */}
      <footer className="mt-20 border-t border-slate-200 bg-white py-12">
        <div className="container mx-auto px-4 text-center">
          <p className="text-sm text-slate-500">
            &copy; 2026 CodeGuard-JS. Built for Local IT Security Analysis & Web Development.
          </p>
          <div className="mt-4 flex justify-center gap-6">
            <a href="#" className="text-slate-400 hover:text-slate-600 transition-colors">Documentation</a>
            <a href="#" className="text-slate-400 hover:text-slate-600 transition-colors">Privacy Policy</a>
            <a href="#" className="text-slate-400 hover:text-slate-600 transition-colors">Changelog</a>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default App
