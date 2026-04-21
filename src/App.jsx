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
      className="min-h-screen bg-white dark:bg-dark-surface transition-colors duration-300 font-sans text-plum-black dark:text-white relative"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Drag Overlay */}
      {isDragging && (
        <div className="fixed inset-0 z-[100] bg-pinterest-red/10 backdrop-blur-[2px] border-4 border-dashed border-pinterest-red m-4 rounded-pinterest-xl flex items-center justify-center pointer-events-none animate-in fade-in zoom-in duration-200">
          <div className="bg-white dark:bg-zinc-900 p-8 rounded-pinterest-lg shadow-2xl flex flex-col items-center gap-4">
            <div className="w-16 h-16 bg-pinterest-red rounded-pinterest flex items-center justify-center text-white shadow-xl shadow-pinterest-red/40">
              <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            </div>
            <p className="text-xl font-bold tracking-tight">Drop files to scan</p>
          </div>
        </div>
      )}
      <input type="file" ref={fileInputRef} onChange={handleFileUpload} multiple className="hidden" accept=".js,.jsx,.ts,.tsx" />
      <input type="file" ref={folderInputRef} onChange={handleFileUpload} webkitdirectory="true" directory="true" className="hidden" />

      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b border-warm-silver/20 bg-white/90 dark:bg-dark-surface/80 backdrop-blur-md">
        <div className="container mx-auto flex h-16 items-center justify-between px-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-pinterest bg-pinterest-red text-white shadow-lg shadow-pinterest-red/20">
              <span className="font-bold text-sm">CG</span>
            </div>
            <h1 className="text-xl font-bold tracking-tight">
              CodeGuard<span className="text-pinterest-red">JS</span>
            </h1>
          </div>

          <div className="flex items-center gap-3">
            <button 
              onClick={() => setDarkMode(!darkMode)}
              className="p-2.5 rounded-full bg-warm-light/50 dark:bg-zinc-800 hover:bg-warm-light transition-colors text-plum-black dark:text-gray-400"
              title="Toggle Theme"
            >
              {darkMode ? (
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
              )}
            </button>
            <button 
              className="btn-primary disabled:opacity-30" 
              disabled={results.length === 0}
            >
              Export Report
            </button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8 max-w-7xl">
        {/* Hero / Upload */}
        <section className={`mb-12 flex items-center justify-between p-8 card-pinterest ${results.length === 0 ? 'flex-col gap-8 text-center py-20 bg-warm-wash' : 'bg-white'}`}>
          <div className={results.length === 0 ? 'max-w-3xl' : 'max-w-xl'}>
            <h2 className={`font-bold tracking-tight ${results.length === 0 ? 'text-5xl mb-4' : 'text-3xl'}`}>
              {results.length === 0 ? 'Analyze your code locally.' : 'Scan Results'}
            </h2>
            <p className="text-olive-gray dark:text-gray-400 text-lg">
              {results.length === 0 
                ? 'CodeGuard-JS scans for security vulnerabilities directly in your browser. No code ever leaves your machine.' 
                : `${files.length} files analyzed. ${stats.totalIssues} vulnerabilities found.`}
            </p>
          </div>
          <div className="flex flex-col items-center gap-4">
            <div className="flex gap-4">
              <button onClick={() => fileInputRef.current.click()} className="btn-secondary">Select Files</button>
              <button onClick={() => folderInputRef.current.click()} className="btn-primary shadow-xl shadow-pinterest-red/20">Analyze Folder</button>
              {results.length > 0 && (
                <button 
                  onClick={() => { setResults([]); setFiles([]); setSelectedFileIdx(null); setLargeProjectWarning(false); }} 
                  className="p-3 bg-sand-gray text-pinterest-red rounded-full hover:bg-warm-light transition-all"
                  title="Clear Results"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                </button>
              )}
            </div>
            {largeProjectWarning && (
              <p className="text-xs font-bold text-orange-600 dark:text-orange-400 uppercase tracking-widest animate-pulse">Large project: scan may take longer.</p>
            )}
          </div>
        </section>

        {results.length > 0 && (
          <>
            {/* Stats Grid */}
            <section className="mb-12 grid grid-cols-2 lg:grid-cols-4 gap-6">
              {[
                { label: 'Files', value: files.length, color: 'text-plum-black dark:text-white' },
                { label: 'Total Issues', value: stats.totalIssues, color: stats.totalIssues > 0 ? 'text-pinterest-red' : 'text-plum-black dark:text-white' },
                { label: 'Critical', value: stats.criticalIssues, color: stats.criticalIssues > 0 ? 'text-red-500' : 'text-plum-black dark:text-white' },
                { label: 'Security Score', value: `${stats.securityScore}%`, color: stats.securityScore > 80 ? 'text-green-600' : stats.securityScore >= 50 ? 'text-orange-500' : 'text-red-500' }
              ].map((s, i) => (
                <div key={i} className="card-pinterest p-6 flex flex-col items-center justify-center bg-white">
                  <span className="text-xs font-bold uppercase tracking-widest text-olive-gray mb-2">{s.label}</span>
                  <span className={`text-3xl font-bold ${s.color}`}>{s.value}</span>
                </div>
              ))}
            </section>

            {/* Masonry-inspired Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
              {/* Sidebar Explorer */}
              <div className="lg:col-span-3 card-pinterest bg-warm-wash/30 dark:bg-zinc-900 overflow-hidden">
                <div className="p-5 border-b border-warm-silver/20 bg-white/50">
                  <h3 className="text-xs font-bold uppercase tracking-widest text-olive-gray">File Explorer</h3>
                </div>
                <div className="max-h-[600px] overflow-y-auto p-3 space-y-1">
                  {results.map((res, idx) => (
                    <button 
                      key={idx} 
                      onClick={() => setSelectedFileIdx(idx)}
                      className={`w-full flex items-center gap-3 px-4 py-3 rounded-pinterest transition-all text-left group ${selectedFileIdx === idx ? 'bg-white shadow-md' : 'hover:bg-white/50'}`}
                    >
                      <div className={`h-2.5 w-2.5 rounded-full shrink-0 ${res.issues.length > 0 ? 'bg-pinterest-red shadow-sm shadow-pinterest-red/50' : (!res.success || res.hasError) ? 'bg-amber-400' : 'bg-green-500'}`}></div>
                      <span className={`text-sm truncate flex-1 font-medium ${selectedFileIdx === idx ? 'text-plum-black font-bold' : 'text-olive-gray'}`}>
                        {res.fileName.split('/').pop()}
                      </span>
                      {res.issues.length > 0 && <span className="text-[10px] font-bold text-olive-gray/60 group-hover:text-pinterest-red">{res.issues.length}</span>}
                    </button>
                  ))}
                </div>
              </div>

              {/* Content Area */}
              <div className="lg:col-span-9 space-y-8">
                {!selectedResult ? (
                  <div className="card-pinterest p-20 flex flex-col items-center justify-center text-center bg-warm-wash/20">
                    <div className="w-20 h-20 bg-warm-light rounded-pinterest flex items-center justify-center mb-6 text-olive-gray">
                      <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                    </div>
                    <h3 className="font-bold text-2xl mb-2">Select a file</h3>
                    <p className="text-olive-gray max-w-sm">Choose a file from the explorer to view detailed security analysis and code snippets.</p>
                  </div>
                ) : !selectedResult.success ? (
                  <div className="card-pinterest p-16 flex flex-col items-center justify-center text-center bg-orange-50/30">
                    <div className="w-24 h-24 bg-orange-100 rounded-full flex items-center justify-center mb-6 text-orange-600">
                      <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    </div>
                    <h3 className="text-2xl font-bold text-plum-black">Parsing Error</h3>
                    <p className="text-olive-gray mt-2 max-w-md">{selectedResult.error || "Syntax issues prevented a complete scan of this file."}</p>
                  </div>
                ) : selectedResult.issues.length === 0 ? (
                  <div className="card-pinterest p-20 flex flex-col items-center justify-center text-center bg-green-50/20">
                    <div className="w-24 h-24 bg-green-100 rounded-full flex items-center justify-center mb-6 text-green-600">
                      <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </div>
                    <h3 className="text-2xl font-bold text-plum-black">Secure File</h3>
                    <p className="text-olive-gray mt-2">No security vulnerabilities were detected in this file.</p>
                  </div>
                ) : (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between px-2">
                      <h3 className="text-xl font-bold">{selectedResult.fileName.split('/').pop()}</h3>
                      <span className="text-xs font-bold px-3 py-1 bg-pinterest-red/10 text-pinterest-red rounded-full">
                        {selectedResult.issues.length} ISSUES FOUND
                      </span>
                    </div>
                    {selectedResult.issues.map((issue, i) => (
                      <div key={i} className="card-pinterest p-8 bg-white border-warm-silver/30 shadow-sm hover:shadow-md transition-shadow">
                        <div className="flex items-start justify-between mb-6">
                          <div className="space-y-2">
                            <div className="flex items-center gap-3">
                              <span className={`text-[10px] font-bold uppercase tracking-widest px-2.5 py-1 rounded-pinterest ${issue.severity === 'CRITICAL' ? 'bg-pinterest-red text-white' : 'bg-sand-gray text-plum-black'}`}>
                                {issue.severity}
                              </span>
                              <span className="text-[10px] font-bold text-warm-silver uppercase">{issue.id}</span>
                            </div>
                            <h4 className="font-bold text-plum-black text-2xl leading-tight">{issue.message}</h4>
                          </div>
                          <div className="text-xs font-bold text-olive-gray bg-warm-light/50 px-4 py-1.5 rounded-full">LINE {issue.line}</div>
                        </div>

                        <p className="text-base text-olive-gray mb-8 leading-relaxed">
                          {issue.suggestion}
                        </p>

                        {/* macOS Code Block Style - Preserved as requested */}
                        <div className="bg-gray-950 dark:bg-black rounded-xl overflow-hidden border border-gray-800 shadow-xl">
                          <div className="px-4 py-2 bg-gray-900/50 border-b border-gray-800 flex items-center gap-1.5">
                             <div className="w-2 h-2 rounded-full bg-red-500/50"></div>
                             <div className="w-2 h-2 rounded-full bg-orange-500/50"></div>
                             <div className="w-2 h-2 rounded-full bg-green-500/50"></div>
                          </div>
                          <div className="p-4 font-mono text-[11px] leading-relaxed overflow-x-auto text-gray-300">
                            {(() => {
                              const lines = selectedResult.rawCode?.split('\n') || [];
                              const target = typeof issue.line === 'number' ? issue.line - 1 : -1;
                              const start = Math.max(0, target - 1);
                              const end = Math.min(lines.length - 1, target + 1);

                              return lines.slice(start, end + 1).map((text, idx) => {
                                const num = start + idx + 1;
                                const isTarget = num === issue.line;
                                return (
                                  <div key={idx} className={`flex gap-4 ${isTarget ? 'text-red-400 bg-red-400/10 -mx-4 px-4 font-bold' : 'opacity-40'}`}>
                                    <span className="w-6 text-right select-none text-gray-600">{num}</span>
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

      <footer className="mt-24 py-16 bg-dark-surface text-white">
        <div className="container mx-auto px-4 flex flex-col items-center">
           <div className="flex items-center gap-3 mb-6">
              <div className="h-8 w-8 rounded-pinterest bg-pinterest-red flex items-center justify-center text-white font-bold text-xs shadow-lg shadow-pinterest-red/20">CG</div>
              <span className="text-sm font-bold uppercase tracking-[0.3em] text-warm-silver">CodeGuard JS</span>
           </div>
           <p className="text-sm text-warm-silver font-medium text-center max-w-md">
             A localized static analysis tool for detecting latent security vulnerabilities in web applications.
           </p>
           <div className="mt-8 text-[10px] font-bold text-warm-silver/40 uppercase tracking-widest">
             © 2026 CodeGuard Protocol • v1.0.0-Beta
           </div>
        </div>
      </footer>
    </div>
  )
}

export default App

