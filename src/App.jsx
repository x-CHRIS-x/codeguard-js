import { useState, useRef, useMemo } from 'react'
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
  const fileInputRef = useRef(null)
  const folderInputRef = useRef(null)

  // Derived stats
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
    <div className="min-h-screen bg-slate-50 font-sans text-slate-900">
      {/* Hidden Inputs */}
      <input type="file" ref={fileInputRef} onChange={handleFileUpload} multiple className="hidden" accept=".js,.jsx,.ts,.tsx" />
      <input type="file" ref={folderInputRef} onChange={handleFileUpload} webkitdirectory="true" directory="true" className="hidden" />

      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b border-slate-200 bg-white/80 backdrop-blur-md">
        <div className="container mx-auto flex h-16 items-center justify-between px-4">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-red-600 text-white shadow-sm">
              <span className="font-bold text-xs uppercase">CG</span>
            </div>
            <h1 className="text-xl font-bold tracking-tight text-slate-900">
              CodeGuard<span className="text-red-600">-JS</span>
            </h1>
          </div>
          <div className="flex items-center gap-4">
            {isScanning && (
              <div className="flex items-center gap-2 text-sm font-medium text-slate-500 animate-pulse">
                <div className="h-2 w-2 rounded-full bg-red-600"></div>
                Scanning...
              </div>
            )}
            <button 
              className="rounded-full bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 transition-all shadow-sm disabled:opacity-30" 
              disabled={results.length === 0}
            >
              Export Report
            </button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Upload Section (Miniaturized if results exist) */}
        <section className={`transition-all duration-500 ${results.length > 0 ? 'mb-8' : 'mb-12 py-10 text-center'}`}>
          {!results.length && (
            <>
              <h2 className="mb-4 text-4xl font-extrabold tracking-tight text-slate-900 sm:text-5xl">Static Security Analysis</h2>
              <p className="mx-auto mb-8 max-w-2xl text-lg text-slate-600">Secure your JavaScript code locally. No data ever leaves your machine.</p>
            </>
          )}
          
          <div className={`mx-auto ${results.length > 0 ? 'max-w-none flex items-center justify-between bg-white p-4 rounded-xl border border-slate-200' : 'max-w-xl'}`}>
            <div className={results.length > 0 ? 'flex items-center gap-4' : ''}>
               {results.length > 0 && <h3 className="font-bold text-slate-700">Ready for new scan?</h3>}
               <div className="flex gap-3">
                  <button onClick={() => fileInputRef.current.click()} className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 shadow-sm">
                    Select Files
                  </button>
                  <button onClick={() => folderInputRef.current.click()} className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 shadow-sm">
                    Select Folder
                  </button>
               </div>
            </div>
            {results.length > 0 && (
              <button onClick={() => { setResults([]); setFiles([]); setSelectedFileIdx(null); }} className="text-sm font-bold text-red-600 hover:underline">
                Clear All
              </button>
            )}
          </div>
        </section>

        {/* Dashboard Stats */}
        <section className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: 'Files Scanned', value: files.length, color: 'text-slate-900' },
            { label: 'Total Issues', value: stats.totalIssues, color: stats.totalIssues > 0 ? 'text-red-600' : 'text-slate-900' },
            { label: 'Critical Risks', value: stats.criticalIssues, color: stats.criticalIssues > 0 ? 'text-red-700' : 'text-slate-900' },
            { label: 'Security Score', value: `${stats.securityScore}%`, color: stats.securityScore > 80 ? 'text-green-600' : 'text-orange-600' }
          ].map((stat, i) => (
            <div key={i} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition-transform hover:scale-[1.02]">
              <p className="text-xs font-bold uppercase tracking-wider text-slate-400">{stat.label}</p>
              <p className={`mt-1 text-3xl font-black ${stat.color}`}>{stat.value}</p>
            </div>
          ))}
        </section>

        {/* Analysis Interface */}
        <div className="grid gap-6 lg:grid-cols-3 h-[600px]">
          {/* File List Panel */}
          <aside className="lg:col-span-1 flex flex-col rounded-xl border border-slate-200 bg-white overflow-hidden shadow-sm">
            <div className="border-b border-slate-100 bg-slate-50/50 px-4 py-3">
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500">Scan Results</h3>
            </div>
            <div className="flex-1 overflow-y-auto divide-y divide-slate-100 font-medium">
              {!results.length ? (
                <div className="flex h-full items-center justify-center p-8 text-center text-sm italic text-slate-400">Upload code to start</div>
              ) : (
                results.map((res, idx) => (
                  <div 
                    key={idx} 
                    onClick={() => setSelectedFileIdx(idx)}
                    className={`flex items-center justify-between px-4 py-4 cursor-pointer transition-all ${selectedFileIdx === idx ? 'bg-red-50 border-l-4 border-red-600' : 'hover:bg-slate-50'}`}
                  >
                    <div className="min-w-0 pr-4">
                      <p className={`text-sm truncate ${selectedFileIdx === idx ? 'text-red-900 font-bold' : 'text-slate-700'}`}>
                        {res.fileName}
                      </p>
                      <p className="text-[10px] text-slate-400 uppercase tracking-tighter">
                        {res.issues.length} Issues found
                      </p>
                    </div>
                    {res.issues.length > 0 ? (
                      <span className="flex h-5 w-5 items-center justify-center rounded-full bg-red-100 text-[10px] font-bold text-red-600">
                        !
                      </span>
                    ) : (
                      <span className="text-green-500">✓</span>
                    )}
                  </div>
                ))
              )}
            </div>
          </aside>

          {/* Details Panel */}
          <section className="lg:col-span-2 flex flex-col rounded-xl border border-slate-200 bg-white overflow-hidden shadow-sm">
            <div className="border-b border-slate-100 bg-slate-50/50 px-4 py-3 flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-700">
                {selectedResult ? selectedResult.fileName : "Select a file to view issues"}
              </h3>
              {selectedResult && (
                <span className="rounded bg-slate-900 px-2 py-0.5 text-[10px] font-bold text-white uppercase">
                  {selectedResult.issues.length} Issues
                </span>
              )}
            </div>
            
            <div className="flex-1 overflow-y-auto p-6">
              {!selectedResult ? (
                <div className="flex h-full flex-col items-center justify-center text-slate-400">
                  <svg className="mb-4 h-12 w-12 opacity-20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <p className="text-sm italic">Click a file on the left to inspect vulnerabilities</p>
                </div>
              ) : selectedResult.issues.length === 0 ? (
                <div className="flex h-full flex-col items-center justify-center text-green-500">
                  <span className="mb-2 text-4xl">🛡️</span>
                  <p className="font-bold">No vulnerabilities detected</p>
                  <p className="text-xs text-slate-400 mt-1">This file appears to follow common security best practices.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {selectedResult.issues.map((issue, i) => (
                    <div key={i} className="rounded-lg border-l-4 border-red-500 bg-red-50/50 p-4 shadow-sm">
                      <div className="mb-2 flex items-center justify-between">
                        <span className="text-[10px] font-black uppercase tracking-widest text-red-600 bg-red-100 px-2 py-0.5 rounded">
                          {issue.id} | {issue.severity}
                        </span>
                        <span className="text-xs font-bold text-slate-400">Line {issue.line}</span>
                      </div>
                      <h4 className="font-bold text-slate-900 mb-1">{issue.message}</h4>
                      <p className="text-sm text-slate-600 mb-3">{issue.suggestion}</p>
                      <div className="bg-slate-950 rounded p-3 font-mono text-[11px] text-red-200 border border-red-900/30 overflow-x-auto shadow-inner">
                        {(() => {
                          const lines = selectedResult.rawCode?.split('\n') || [];
                          const targetLine = issue.line - 1; // 0-based
                          
                          // Show 1 line of context before and after if possible
                          const start = Math.max(0, targetLine - 1);
                          const end = Math.min(lines.length - 1, targetLine + 1);
                          
                          return lines.slice(start, end + 1).map((lineText, idx) => {
                            const currentLineNum = start + idx + 1;
                            const isTarget = currentLineNum === issue.line;
                            
                            return (
                              <div key={idx} className={`${isTarget ? 'bg-red-950/50 -mx-3 px-3 border-l-2 border-red-500 text-red-100 font-bold' : 'opacity-40'}`}>
                                <span className="inline-block w-8 select-none text-slate-600 text-right mr-4">{currentLineNum}</span>
                                <code>{lineText || ' '}</code>
                              </div>
                            );
                          });
                        })()}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>
        </div>
      </main>

      {/* Footer */}
      <footer className="mt-20 border-t border-slate-200 bg-white py-12">
        <div className="container mx-auto px-4 text-center">
          <p className="text-xs font-bold uppercase tracking-widest text-slate-400">&copy; 2026 CodeGuard-JS</p>
          <p className="mt-2 text-sm text-slate-500">Local IT Security Analysis & Web Development Compliance Tool</p>
        </div>
      </footer>
    </div>
  )
}

export default App
