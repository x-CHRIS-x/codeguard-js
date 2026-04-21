import { useState, useRef, useMemo, useEffect } from 'react'
import { scanFile } from './utils/scannerEngine'
import { injectionRules } from './scanner/rules/injection'
import { xssRules } from './scanner/rules/xss'
import { authRules } from './scanner/rules/auth'
import { sensitiveDataRules } from './scanner/rules/sensitiveData'
import { misconfigRules } from './scanner/rules/misconfig'
import { deserializationRules } from './scanner/rules/deserialization'
import { knownVulnsRules } from './scanner/rules/knownVulns'
import './App.css'

function App() {
  const [files, setFiles] = useState([])
  const [results, setResults] = useState([])
  const [isScanning, setIsScanning] = useState(false)
  const [selectedFileIdx, setSelectedFileIdx] = useState(null)
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('theme')
    if (saved) return saved === 'dark'
    return window.matchMedia('(prefers-color-scheme: dark)').matches
  })
  const [largeProjectWarning, setLargeProjectWarning] = useState(false)
  const [isDragging, setIsDragging] = useState(false)

  const fileInputRef = useRef(null)
  const folderInputRef = useRef(null)

  // Handle Dark Mode Class and Persistence
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark')
      localStorage.setItem('theme', 'dark')
    } else {
      document.documentElement.classList.remove('dark')
      localStorage.setItem('theme', 'light')
    }
  }, [darkMode])

  const stats = useMemo(() => {
    const totalIssues = results.reduce((acc, res) => acc + (res.issues?.length || 0), 0)
    const criticalIssues = results.reduce((acc, res) => 
      acc + (res.issues?.filter(i => i.severity === 'CRITICAL').length || 0), 0)
    
    const WEIGHTS = { CRITICAL: 20, HIGH: 10, MEDIUM: 5, LOW: 1 }
    const penalty = results.reduce((acc, res) => 
      acc + (res.issues?.reduce((sum, issue) => 
        sum + (WEIGHTS[issue.severity] || 5), 0) || 0), 0)

    const securityScore = results.length > 0 
      ? Math.max(0, 100 - penalty) 
      : 100

    return { totalIssues, criticalIssues, securityScore }
  }, [results])

  const handleFileUpload = (e) => {
    const uploadedFiles = Array.from(e.target.files)
    processFiles(uploadedFiles)
  }

  const handleDragOver = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(true)
  }

  const handleDragLeave = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }

  const handleDrop = async (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)

    const items = e.dataTransfer.items
    if (!items) return

    const filesToProcess = []
    
    const traverseFileTree = async (item, path = "") => {
      if (item.isFile) {
        return new Promise((resolve) => {
          item.file((file) => {
            Object.defineProperty(file, 'webkitRelativePath', {
              value: path + file.name,
              writable: false
            })
            filesToProcess.push(file)
            resolve()
          })
        })
      } else if (item.isDirectory) {
        const dirReader = item.createReader()
        const entries = await new Promise((resolve) => {
          dirReader.readEntries((entries) => resolve(entries))
        })
        for (const entry of entries) {
          await traverseFileTree(entry, path + item.name + "/")
        }
      }
    }

    const traversePromises = []
    for (let i = 0; i < items.length; i++) {
      const item = items[i].webkitGetAsEntry()
      if (item) {
        traversePromises.push(traverseFileTree(item))
      }
    }

    await Promise.all(traversePromises)
    processFiles(filesToProcess)
  }

  const processFiles = async (fileList) => {
    setIsScanning(true)
    setSelectedFileIdx(null)
    setLargeProjectWarning(false)

    const filtered = fileList.filter(file => {
      const path = file.webkitRelativePath || file.name
      const isHidden = path.split('/').some(part => part.startsWith('.'))
      const isNodeModules = path.includes('node_modules')
      const isDist = path.includes('dist') || path.includes('build')
      const extension = path.split('.').pop().toLowerCase()
      const isSupported = ['js', 'jsx', 'ts', 'tsx'].includes(extension)

      return !isHidden && !isNodeModules && !isDist && isSupported
    })

    if (filtered.length > 50) {
      setLargeProjectWarning(true)
    }

    setFiles(filtered)
    const scanResults = []
    const allRules = [
      ...injectionRules, ...xssRules, ...authRules,
      ...sensitiveDataRules, ...misconfigRules,
      ...deserializationRules, ...knownVulnsRules
    ]

    for (const file of filtered) {
      const result = await scanFile(file, allRules)
      scanResults.push(result)
    }

    setResults(scanResults)
    setIsScanning(false)
    if (scanResults.length > 0) setSelectedFileIdx(0)
  }

  const selectedResult = selectedFileIdx !== null ? results[selectedFileIdx] : null

  return (
    <div 
      className="min-h-screen bg-eleven-white dark:bg-[#0a0a0a] transition-colors duration-300 font-sans text-eleven-black dark:text-eleven-light-gray relative"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Drag Overlay */}
      {isDragging && (
        <div className="fixed inset-0 z-[100] bg-eleven-black/5 backdrop-blur-[2px] border-2 border-dashed border-eleven-black/20 m-6 rounded-eleven-xl flex items-center justify-center pointer-events-none animate-in fade-in zoom-in duration-200">
          <div className="bg-white dark:bg-zinc-900 p-10 rounded-eleven-xl shadow-eleven-card flex flex-col items-center gap-6">
            <div className="w-20 h-20 bg-eleven-black rounded-pill flex items-center justify-center text-white">
              <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            </div>
            <p className="text-2xl font-display font-[300] tracking-tight">Drop project to scan</p>
          </div>
        </div>
      )}
      <input type="file" ref={fileInputRef} onChange={handleFileUpload} multiple className="hidden" accept=".js,.jsx,.ts,.tsx" />
      <input type="file" ref={folderInputRef} onChange={handleFileUpload} webkitdirectory="true" directory="true" className="hidden" />

      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b border-border-subtle bg-white/80 dark:bg-[#0a0a0a]/80 backdrop-blur-xl">
        <div className="container mx-auto flex h-20 items-center justify-between px-6">
          <div className="flex items-center gap-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-pill bg-eleven-black text-white shadow-eleven-button">
              <span className="font-bold text-xs uppercase tracking-widest">CG</span>
            </div>
            <h1 className="text-xl font-display font-[300] tracking-tight">
              CodeGuard <span className="text-warm-gray">Protocol</span>
            </h1>
          </div>

          <div className="flex items-center gap-4">
            <button 
              onClick={() => setDarkMode(!darkMode)}
              className="p-3 rounded-pill bg-eleven-light-gray dark:bg-zinc-800 hover:bg-eleven-border transition-colors text-eleven-black dark:text-gray-400"
              title="Toggle Theme"
            >
              {darkMode ? (
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
              )}
            </button>
            <button 
              className="btn-pill-black disabled:opacity-30 disabled:pointer-events-none text-[15px] font-medium" 
              disabled={results.length === 0}
            >
              Export Report
            </button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-6 py-12 max-w-7xl">
        {/* Hero / Upload */}
        <section className={`mb-16 flex items-center justify-between ${results.length === 0 ? 'flex-col gap-12 text-center py-28' : 'flex-row p-10 card-eleven'}`}>
          <div className={results.length === 0 ? 'max-w-4xl' : 'max-w-2xl'}>
            <h2 className={`font-display font-[300] tracking-tight text-eleven-black dark:text-white ${results.length === 0 ? 'text-[64px] leading-[1.05] mb-8' : 'text-4xl'}`}>
              {results.length === 0 ? 'Security analysis, refined.' : 'Scan Complete'}
            </h2>
            <p className="body-text text-dark-gray dark:text-gray-400 max-w-2xl mx-auto">
              {results.length === 0 
                ? 'Localized static analysis for modern web development. Detect vulnerabilities instantly without ever leaving your browser environment.' 
                : `${files.length} sources analyzed. ${stats.totalIssues} vulnerabilities identified across the project architecture.`}
            </p>
          </div>
          <div className="flex flex-col items-center gap-6">
            <div className="flex gap-4">
              <button onClick={() => fileInputRef.current.click()} className="btn-pill-white">Select Files</button>
              <button onClick={() => folderInputRef.current.click()} className="btn-warm-stone">Analyze Folder</button>
              {results.length > 0 && (
                <button 
                  onClick={() => { setResults([]); setFiles([]); setSelectedFileIdx(null); setLargeProjectWarning(false); }} 
                  className="p-3.5 bg-eleven-light-gray text-eleven-black rounded-pill hover:bg-eleven-border transition-all shadow-eleven-card"
                  title="Reset"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                </button>
              )}
            </div>
            {largeProjectWarning && (
              <p className="text-[11px] font-bold text-warm-gray uppercase tracking-[0.2em] animate-pulse">Intensive project scan: Processing...</p>
            )}
          </div>
        </section>

        {results.length > 0 && (
          <>
            {/* Stats Row */}
            <section className="mb-16 grid grid-cols-2 lg:grid-cols-4 gap-8">
              {[
                { label: 'Files Analyzed', value: files.length, color: 'text-eleven-black dark:text-white' },
                { label: 'Vulnerabilities', value: stats.totalIssues, color: stats.totalIssues > 0 ? 'text-eleven-black' : 'text-eleven-black dark:text-white' },
                { label: 'Critical Risks', value: stats.criticalIssues, color: stats.criticalIssues > 0 ? 'text-eleven-black' : 'text-eleven-black dark:text-white' },
                { label: 'Security Grade', value: `${stats.securityScore}%`, color: stats.securityScore > 80 ? 'text-eleven-black' : 'text-eleven-black' }
              ].map((s, i) => (
                <div key={i} className="card-eleven p-8 flex flex-col items-center justify-center bg-white text-center">
                  <span className="text-[11px] font-bold uppercase tracking-[0.25em] text-warm-gray mb-3">{s.label}</span>
                  <span className={`text-3xl font-display font-[300] ${s.color}`}>{s.value}</span>
                </div>
              ))}
            </section>

            {/* Architecture Viewer */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
              {/* File Navigator */}
              <div className="lg:col-span-4 card-eleven bg-eleven-light-gray/40 dark:bg-zinc-900/40 border-none shadow-none">
                <div className="p-6 border-b border-border-subtle bg-white/50 backdrop-blur-sm">
                  <h3 className="text-[11px] font-bold uppercase tracking-[0.25em] text-warm-gray">Project Architecture</h3>
                </div>
                <div className="max-h-[650px] overflow-y-auto p-4 space-y-2">
                  {results.map((res, idx) => (
                    <button 
                      key={idx} 
                      onClick={() => setSelectedFileIdx(idx)}
                      className={`w-full flex items-center gap-4 px-5 py-4 rounded-eleven-md transition-all text-left group ${selectedFileIdx === idx ? 'bg-white shadow-eleven-card ring-1 ring-eleven-black/5' : 'hover:bg-white/40'}`}
                    >
                      <div className={`h-2 w-2 rounded-pill shrink-0 ${res.issues.length > 0 ? 'bg-eleven-black shadow-lg shadow-eleven-black/20' : (!res.success || res.hasError) ? 'bg-warm-stone' : 'bg-eleven-light-gray'}`}></div>
                      <span className={`text-[15px] truncate flex-1 font-medium tracking-[0.15px] ${selectedFileIdx === idx ? 'text-eleven-black font-semibold' : 'text-dark-gray'}`}>
                        {res.fileName.split('/').pop()}
                      </span>
                      {res.issues.length > 0 && <span className="text-[11px] font-bold text-warm-gray">{res.issues.length}</span>}
                    </button>
                  ))}
                </div>
              </div>

              {/* Vulnerability Inspector */}
              <div className="lg:col-span-8 space-y-10">
                {!selectedResult ? (
                  <div className="card-eleven p-24 flex flex-col items-center justify-center text-center bg-white border-dashed border-2 border-eleven-border/50">
                    <div className="w-24 h-24 bg-eleven-light-gray rounded-pill flex items-center justify-center mb-8 text-warm-gray">
                      <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                    </div>
                    <h3 className="font-display font-[300] text-3xl mb-3 text-eleven-black">Select a source file</h3>
                    <p className="body-text text-dark-gray max-w-sm">Detailed security analysis and code visualizations will appear here once a file is selected.</p>
                  </div>
                ) : !selectedResult.success ? (
                  <div className="card-eleven p-20 flex flex-col items-center justify-center text-center bg-white">
                    <div className="w-24 h-24 bg-[#fef2f2] rounded-pill flex items-center justify-center mb-8 text-red-600">
                      <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    </div>
                    <h3 className="text-3xl font-display font-[300] text-eleven-black">Parsing Anomaly</h3>
                    <p className="body-text text-dark-gray mt-4 max-w-lg">{selectedResult.error || "The source code could not be fully parsed due to architectural syntax errors."}</p>
                  </div>
                ) : selectedResult.issues.length === 0 ? (
                  <div className="card-eleven p-24 flex flex-col items-center justify-center text-center bg-white shadow-warm-lift">
                    <div className="w-28 h-28 bg-warm-stone/20 rounded-pill flex items-center justify-center mb-8 text-dark-gray">
                      <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </div>
                    <h3 className="text-3xl font-display font-[300] text-eleven-black">Secure Architecture</h3>
                    <p className="body-text text-dark-gray mt-4">No known vulnerability patterns were identified in this source file.</p>
                  </div>
                ) : (
                  <div className="space-y-10">
                    <div className="flex items-center justify-between px-2">
                      <h3 className="text-2xl font-display font-[300] text-eleven-black">{selectedResult.fileName.split('/').pop()}</h3>
                      <span className="text-[11px] font-bold tracking-[0.25em] text-warm-gray uppercase">
                        {selectedResult.issues.length} Findings
                      </span>
                    </div>
                    {selectedResult.issues.map((issue, i) => (
                      <div key={i} className="card-eleven p-10 bg-white border-border-subtle hover:shadow-warm-lift transition-all duration-500">
                        <div className="flex items-start justify-between mb-8">
                          <div className="space-y-3">
                            <div className="flex items-center gap-4">
                              <span className={`text-[10px] font-bold uppercase tracking-[0.2em] px-3 py-1.5 rounded-pill ${issue.severity === 'CRITICAL' ? 'bg-eleven-black text-white' : 'bg-eleven-light-gray text-dark-gray'}`}>
                                {issue.severity}
                              </span>
                              <span className="text-[10px] font-bold text-warm-gray uppercase tracking-widest">{issue.id}</span>
                            </div>
                            <h4 className="font-display font-[300] text-eleven-black text-3xl leading-[1.15]">{issue.message}</h4>
                          </div>
                          <div className="text-[11px] font-bold text-warm-gray bg-eleven-light-gray/50 px-5 py-2 rounded-pill">LINE {issue.line}</div>
                        </div>

                        <p className="body-text text-dark-gray mb-10 leading-relaxed">
                          {issue.suggestion}
                        </p>

                        {/* macOS Code Block Style - Preserved as requested */}
                        <div className="bg-gray-950 dark:bg-black rounded-eleven-lg overflow-hidden border border-gray-800 shadow-xl">
                          <div className="px-5 py-3 bg-gray-900/50 border-b border-gray-800 flex items-center gap-2">
                             <div className="w-2.5 h-2.5 rounded-pill bg-red-500/50"></div>
                             <div className="w-2.5 h-2.5 rounded-pill bg-orange-500/50"></div>
                             <div className="w-2.5 h-2.5 rounded-pill bg-green-500/50"></div>
                          </div>
                          <div className="p-6 font-mono text-[13px] leading-[1.85] overflow-x-auto text-gray-300">
                            {(() => {
                              const lines = selectedResult.rawCode?.split('\n') || [];
                              const target = typeof issue.line === 'number' ? issue.line - 1 : -1;
                              const start = Math.max(0, target - 1);
                              const end = Math.min(lines.length - 1, target + 1);

                              return lines.slice(start, end + 1).map((text, idx) => {
                                const num = start + idx + 1;
                                const isTarget = num === issue.line;
                                return (
                                  <div key={idx} className={`flex gap-6 ${isTarget ? 'text-red-300 bg-red-400/10 -mx-6 px-6 font-semibold' : 'opacity-30'}`}>
                                    <span className="w-8 text-right select-none text-gray-600">{num}</span>
                                    <code className="whitespace-pre">{text || ' '}</code>
                                  </div>
                                );
                              });
                            })()}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </main>

      <footer className="mt-32 py-24 bg-eleven-light-gray border-t border-border-subtle">
        <div className="container mx-auto px-6 flex flex-col items-center">
           <div className="flex items-center gap-4 mb-10">
              <div className="h-10 w-10 rounded-pill bg-eleven-black flex items-center justify-center text-white font-bold text-xs shadow-eleven-button">CG</div>
              <span className="text-[12px] font-bold uppercase tracking-[0.4em] text-warm-gray">CodeGuard Protocol</span>
           </div>
           <p className="body-text text-warm-gray text-center max-w-xl text-base">
             Building a more secure web through precise, browser-native static analysis and architectural security verification.
           </p>
           <div className="mt-12 flex gap-8">
              <span className="text-[10px] font-bold text-warm-gray/40 uppercase tracking-[0.2em]">v1.0.0-Beta</span>
              <span className="text-[10px] font-bold text-warm-gray/40 uppercase tracking-[0.2em]">© 2026 Protocol Lab</span>
           </div>
        </div>
      </footer>
    </div>
  )
}

export default App

