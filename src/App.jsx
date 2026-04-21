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
  const [darkMode, setDarkMode] = useState(false)
  const [largeProjectWarning, setLargeProjectWarning] = useState(false)

  const fileInputRef = useRef(null)
  const folderInputRef = useRef(null)

  // Handle Dark Mode Class
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [darkMode])

  const stats = useMemo(() => {
    const totalIssues = results.reduce((acc, res) => acc + (res.issues?.length || 0), 0)
    const criticalIssues = results.reduce((acc, res) => 
      acc + (res.issues?.filter(i => i.severity === 'CRITICAL').length || 0), 0)
    const securityScore = results.length > 0 
      ? Math.max(0, 100 - (totalIssues * 5)) 
      : 100

    return { totalIssues, criticalIssues, securityScore }
  }, [results])

  const handleFileUpload = (e) => {
    const uploadedFiles = Array.from(e.target.files)
    processFiles(uploadedFiles)
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
    <div className="min-h-screen bg-eleven-light-gray transition-colors duration-300 dark:bg-[#0a0a0a] font-sans text-eleven-black dark:text-slate-100">
      <input type="file" ref={fileInputRef} onChange={handleFileUpload} multiple className="hidden" accept=".js,.jsx,.ts,.tsx" />
      <input type="file" ref={folderInputRef} onChange={handleFileUpload} webkitdirectory="true" directory="true" className="hidden" />

      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b border-eleven-border dark:border-zinc-800 bg-white/80 dark:bg-zinc-950/80 backdrop-blur-md">
        <div className="container mx-auto flex h-16 items-center justify-between px-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-eleven-black text-white shadow-lg shadow-eleven-black/20">
              <span className="font-bold text-sm">CG</span>
            </div>
            <h1 className="text-xl font-display font-[300] tracking-tight">
              CodeGuard<span className="text-eleven-black font-sans font-bold">JS</span>
            </h1>
          </div>

          <div className="flex items-center gap-3">
            {largeProjectWarning && (
              <div className="hidden md:flex items-center gap-2 px-3 py-1 bg-warm-stone dark:bg-amber-900/30 text-dark-gray dark:text-amber-400 text-[10px] font-bold rounded-lg border border-eleven-border dark:border-amber-800 animate-pulse">
                <span>⚠️ LARGE PROJECT (50+ FILES)</span>
              </div>
            )}
            <button 
              onClick={() => setDarkMode(!darkMode)}
              className="p-2 rounded-lg hover:bg-eleven-light-gray dark:hover:bg-slate-800 transition-colors text-dark-gray dark:text-slate-400"
              title="Toggle Theme"
            >
              {darkMode ? (
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
              )}
            </button>
            <button 
              className="rounded-lg bg-eleven-black dark:bg-slate-100 px-4 py-2 text-sm font-bold text-white dark:text-slate-900 hover:opacity-90 transition-all disabled:opacity-30" 
              disabled={results.length === 0}
            >
              Export PDF
            </button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8 max-w-7xl">
        {/* Simplified Upload */}
        <section className={`mb-8 flex items-center justify-between p-6 rounded-2xl bg-white dark:bg-slate-900 border border-eleven-border dark:border-slate-800 shadow-sm transition-all ${results.length === 0 ? 'flex-col gap-6 text-center py-16' : ''}`}>
          <div className={results.length === 0 ? 'max-w-2xl' : ''}>
            <h2 className="text-2xl font-display font-[300] tracking-tight">{results.length === 0 ? 'Start Local Security Scan' : 'Project Analysis'}</h2>
            <p className="text-dark-gray dark:text-slate-400 mt-1 font-sans tracking-[0.16px]">{results.length === 0 ? 'Upload your JavaScript project to detect vulnerabilities instantly without leaving your browser.' : `${files.length} files processed. Select one to view issues.`}</p>
          </div>
          <div className="flex flex-col items-center gap-3">
            <div className="flex gap-3">
              <button onClick={() => fileInputRef.current.click()} className="px-5 py-2.5 rounded-xl border border-eleven-border dark:border-slate-700 font-bold text-sm hover:bg-eleven-light-gray dark:hover:bg-slate-800 transition-colors">Select Files</button>
              <button onClick={() => folderInputRef.current.click()} className="px-5 py-2.5 rounded-xl bg-eleven-black text-white font-bold text-sm hover:opacity-90 transition-shadow shadow-lg shadow-eleven-black/20">Analyze Folder</button>
              {results.length > 0 && (
                <button onClick={() => { setResults([]); setFiles([]); setSelectedFileIdx(null); setLargeProjectWarning(false); }} className="p-2.5 text-eleven-black hover:bg-warm-stone dark:hover:bg-red-900/20 rounded-xl transition-colors" title="Clear All">
                  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                </button>
              )}
            </div>
            {largeProjectWarning && results.length === 0 && (
              <p className="text-[10px] font-bold text-dark-gray dark:text-amber-500 uppercase tracking-widest animate-pulse">Large project detected. Scan may be slower.</p>
            )}
          </div>
        </section>

        {/* Stats Row */}
        <section className="mb-8 grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: 'Files', value: files.length, color: 'text-eleven-black dark:text-white' },
            { label: 'Issues', value: stats.totalIssues, color: stats.totalIssues > 0 ? 'text-eleven-black' : 'text-eleven-black dark:text-white' },
            { label: 'Critical', value: stats.criticalIssues, color: stats.criticalIssues > 0 ? 'text-eleven-black' : 'text-eleven-black dark:text-white' },
            { label: 'Score', value: `${stats.securityScore}%`, color: 'text-eleven-black' }
          ].map((s, i) => (
            <div key={i} className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-eleven-border dark:border-slate-800 shadow-sm flex flex-col items-center justify-center">
              <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-warm-gray mb-1">{s.label}</span>
              <span className={`text-2xl font-display font-[300] ${s.color}`}>{s.value}</span>
            </div>
          ))}
        </section>

        {/* Main Workspace */}
        <div className="flex flex-col lg:flex-row gap-6 h-[700px]">
          {/* File Browser */}
          <div className="w-full lg:w-80 flex flex-col bg-white dark:bg-zinc-900 rounded-2xl border border-eleven-border dark:border-zinc-800 overflow-hidden shadow-sm">
            <div className="p-4 border-b border-eleven-light-gray dark:border-zinc-800 flex justify-between items-center bg-eleven-light-gray/20">
              <span className="text-xs font-bold uppercase tracking-widest text-warm-gray">Explorer</span>
              {isScanning && <div className="h-1.5 w-1.5 rounded-full bg-eleven-black animate-ping"></div>}
            </div>
            <div className="flex-1 overflow-y-auto p-2 space-y-1">
              {results.map((res, idx) => (
                <button 
                  key={idx} 
                  onClick={() => setSelectedFileIdx(idx)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all text-left group ${selectedFileIdx === idx ? 'bg-eleven-light-gray dark:bg-zinc-800' : 'hover:bg-eleven-light-gray/50 dark:hover:bg-slate-800/50'}`}
                >
                  <div className={`h-2 w-2 rounded-full shrink-0 ${res.issues.length > 0 ? 'bg-eleven-black shadow-sm shadow-eleven-black/50' : (!res.success || res.hasError) ? 'bg-warm-stone' : 'bg-eleven-light-gray'}`}></div>
                  <span className={`text-sm truncate flex-1 font-medium tracking-[0.15px] ${selectedFileIdx === idx ? 'text-eleven-black dark:text-white' : 'text-dark-gray dark:text-gray-400'}`}>
                    {res.fileName.split('/').pop()}
                  </span>
                  {res.issues.length > 0 && <span className="text-[10px] font-bold text-warm-gray group-hover:text-eleven-black">{res.issues.length}</span>}
                </button>
              ))}
              {results.length === 0 && <p className="text-center text-xs text-warm-gray mt-10 italic">No files yet</p>}
            </div>
          </div>

          {/* Code & Issue Viewer */}
          <div className="flex-1 flex flex-col bg-white dark:bg-zinc-900 rounded-2xl border border-eleven-border dark:border-zinc-800 overflow-hidden shadow-sm">
            <div className="p-4 border-b border-eleven-light-gray dark:border-zinc-800 bg-eleven-light-gray/20 dark:bg-zinc-800/30 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold truncate max-w-[300px] font-sans tracking-[0.15px]">{selectedResult?.fileName || 'Viewer'}</span>
              </div>
              {selectedResult && selectedResult.issues.length > 0 && <span className="text-[10px] font-bold px-2 py-1 bg-warm-stone text-eleven-black rounded-md uppercase tracking-widest font-sans">Findings Detected</span>}
            </div>

            <div className="flex-1 overflow-y-auto scrollbar-thin scrollbar-thumb-eleven-border dark:scrollbar-thumb-slate-700">
              {!selectedResult ? (
                <div className="h-full flex flex-col items-center justify-center p-10 text-center opacity-40">
                  <div className="w-16 h-16 bg-eleven-light-gray dark:bg-zinc-800 rounded-2xl flex items-center justify-center mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                  </div>
                  <h3 className="font-display font-[300] text-lg text-eleven-black">No Selection</h3>
                  <p className="text-sm font-sans">Select a scanned file from the explorer to see detailed security analysis.</p>
                </div>
              ) : !selectedResult.success ? (
                <div className="h-full flex flex-col items-center justify-center text-warm-gray p-10 text-center">
                  <div className="w-20 h-20 bg-warm-stone rounded-full flex items-center justify-center mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                  </div>
                  <h3 className="text-xl font-display font-[300] uppercase tracking-tight text-eleven-black dark:text-gray-100">Parse Error</h3>
                  <p className="text-sm text-dark-gray mt-1 max-w-sm mx-auto font-sans">{selectedResult.error || "This file could not be parsed. It may contain syntax errors or non-standard syntax that prevents a full scan."}</p>
                </div>
              ) : selectedResult.issues.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-eleven-black">
                  <div className="w-20 h-20 bg-warm-stone/50 dark:bg-green-900/20 rounded-full flex items-center justify-center mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                  </div>
                  <h3 className="text-xl font-display font-[300]">Secure Environment</h3>
                  <p className="text-sm text-warm-gray mt-1 font-sans">No known security patterns detected in this file.</p>
                </div>
              ) : (
                <div className="divide-y divide-eleven-light-gray dark:divide-gray-800">
                  {selectedResult.issues.map((issue, i) => (
                    <div key={i} className="p-6 transition-colors hover:bg-eleven-light-gray/30 dark:hover:bg-gray-800/20">
                      <div className="flex items-start justify-between mb-4">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                             <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded ${issue.severity === 'CRITICAL' ? 'bg-eleven-black text-white' : 'bg-warm-stone text-dark-gray'}`}>
                              {issue.severity}
                            </span>
                            <span className="text-[10px] font-bold text-warm-gray uppercase tracking-tighter">{issue.id}</span>
                          </div>
                          <h4 className="font-display font-[300] text-eleven-black dark:text-white text-2xl leading-tight">{issue.message}</h4>
                        </div>
                        <div className="text-xs font-bold text-warm-gray whitespace-nowrap bg-eleven-light-gray px-3 py-1 rounded-full">LINE {issue.line}</div>
                      </div>

                      <p className="text-sm text-dark-gray dark:text-gray-400 mb-6 font-sans text-base leading-relaxed">
                        {issue.suggestion}
                      </p>

                      <div className="bg-slate-950 dark:bg-black rounded-xl overflow-hidden border border-slate-800 shadow-xl">
                        <div className="px-4 py-2 bg-slate-900/50 border-b border-slate-800 flex items-center gap-1.5">
                           <div className="w-2 h-2 rounded-full bg-red-500/50"></div>
                           <div className="w-2 h-2 rounded-full bg-orange-500/50"></div>
                           <div className="w-2 h-2 rounded-full bg-green-500/50"></div>
                        </div>
                        <div className="p-4 font-mono text-[13px] leading-relaxed overflow-x-auto text-gray-300">
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
        </div>
      </main>

      <footer className="mt-20 py-12 border-t border-eleven-border dark:border-zinc-800">
        <div className="container mx-auto px-4 flex flex-col items-center">
           <div className="flex items-center gap-2 mb-4">
              <div className="h-6 w-6 rounded bg-eleven-black flex items-center justify-center text-white font-bold text-[10px]">CG</div>
              <span className="text-xs font-bold uppercase tracking-[0.3em] text-warm-gray font-display font-[300]">CodeGuard Protocol</span>
           </div>
           <p className="text-xs text-warm-gray font-medium font-sans">v1.0.0-Beta • Architectural Security Verification • 2026</p>
        </div>
      </footer>
    </div>
  )
}

export default App
