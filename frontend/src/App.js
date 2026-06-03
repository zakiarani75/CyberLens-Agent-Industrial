import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [preview, setPreview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [activeTab, setActiveTab] = useState('scan');
  const [history, setHistory] = useState([]);
  const [showReport, setShowReport] = useState(false);
  const [scanId, setScanId] = useState(null);
  const fileInputRef = useRef(null);

  useEffect(() => {
    fetchDashboard();
    fetchHistory();
  }, []);

  const fetchDashboard = async () => {
    try {
      const res = await axios.get('http://localhost:8000/api/dashboard');
      setDashboard(res.data);
    } catch (err) {
      console.error('Dashboard fetch error:', err);
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await axios.get('http://localhost:8000/api/history');
      setHistory(res.data.scans || []);
    } catch (err) {
      console.error('History fetch error:', err);
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSelectedFile(file);
      setPreview(URL.createObjectURL(file));
      setScanResult(null);
      setShowReport(false);
    }
  };

  const handleScan = async () => {
    if (!selectedFile) {
      alert('Please select a QR code image first');
      return;
    }

    setLoading(true);
    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const res = await axios.post('http://localhost:8000/api/qr/scan', formData);
      setScanResult(res.data);
      setScanId(res.data.scan_id);
      setShowReport(true);
      fetchDashboard();
      fetchHistory();
    } catch (err) {
      alert('Scan error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setPreview(null);
    setScanResult(null);
    setShowReport(false);
    setScanId(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const downloadPdfReport = async () => {
    if (!scanId) {
      alert('No scan available for report');
      return;
    }

    try {
      const res = await axios.get('http://localhost:8000/api/report/pdf/' + scanId, {
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'CyberLens_Report_' + scanId + '.pdf');
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert('Download error: ' + err.message);
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    if (score >= 40) return 'text-orange-500';
    return 'text-red-600';
  };

  const getScoreBg = (score) => {
    if (score >= 80) return 'bg-green-500';
    if (score >= 60) return 'bg-yellow-500';
    if (score >= 40) return 'bg-orange-500';
    return 'bg-red-500';
  };

  const getThreatBadge = (level) => {
    switch(level) {
      case 'Safe': return 'bg-green-100 text-green-800 border-green-300';
      case 'Medium Risk': return 'bg-yellow-100 text-yellow-800 border-yellow-300';
      case 'Suspicious': return 'bg-orange-100 text-orange-800 border-orange-300';
      case 'Dangerous': return 'bg-red-100 text-red-800 border-red-300';
      default: return 'bg-gray-100 text-gray-800 border-gray-300';
    }
  };

  const ReportCard = ({ title, children }) => (
    <div className="glass-card p-6 mb-4">
      <h3 className="text-lg font-semibold text-gray-900 mb-4 pb-2 border-b border-gray-200">
        {title}
      </h3>
      {children}
    </div>
  );

  const DataRow = ({ label, value, color }) => (
    <div className="flex justify-between py-2 border-b border-gray-100 last:border-0">
      <span className="text-gray-600">{label}</span>
      <span className={'font-medium ' + (color || 'text-gray-900')}>{value || 'N/A'}</span>
    </div>
  );

  const ScoreBar = ({ label, score }) => (
    <div className="mb-3">
      <div className="flex justify-between mb-1">
        <span className="text-sm text-gray-600">{label}</span>
        <span className={'text-sm font-bold ' + getScoreColor(score)}>{score}/100</span>
      </div>
      <div className="w-full bg-gray-200 rounded-full h-2.5">
        <div
          className={'h-2.5 rounded-full ' + getScoreBg(score)}
          style={{ width: score + '%' }}
        ></div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-pink-bg">
      {/* Header */}
      <header className="bg-green-light shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex justify-between items-center">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">CyberLens Agent</h1>
              <p className="text-sm text-gray-600">Developed By Zakia Rani</p>
            </div>
            <div className="flex space-x-2">
              <button
                onClick={() => setActiveTab('scan')}
                className={'px-4 py-2 rounded-lg text-sm font-medium transition ' + (activeTab === 'scan' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-700 hover:bg-white/50')}
              >
                Scanner
              </button>
              <button
                onClick={() => setActiveTab('dashboard')}
                className={'px-4 py-2 rounded-lg text-sm font-medium transition ' + (activeTab === 'dashboard' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-700 hover:bg-white/50')}
              >
                Dashboard
              </button>
              <button
                onClick={() => setActiveTab('history')}
                className={'px-4 py-2 rounded-lg text-sm font-medium transition ' + (activeTab === 'history' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-700 hover:bg-white/50')}
              >
                History
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 py-6">
        
        {/* SCANNER TAB */}
        {activeTab === 'scan' && (
          <div>
            {/* Upload Area */}
            <div className="glass-card p-8 mb-6 text-center">
              <h2 className="text-xl font-semibold text-gray-900 mb-6">
                QR Code Scanner
              </h2>
              
              <div 
                className="border-2 border-dashed border-gray-300 rounded-xl p-10 mb-6 hover:border-green-400 transition cursor-pointer"
                onClick={() => fileInputRef.current?.click()}
              >
                {preview ? (
                  <div>
                    <img 
                      src={preview} 
                      alt="QR Code Preview" 
                      className="mx-auto max-h-64 rounded-lg shadow-sm"
                    />
                    <p className="text-sm text-gray-500 mt-3">
                      Click to change image
                    </p>
                  </div>
                ) : (
                  <div>
                    <div className="text-gray-400 mb-3">
                      <svg className="mx-auto h-16 w-16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                      </svg>
                    </div>
                    <p className="text-gray-500 text-lg mb-1">
                      Drop your QR code image here
                    </p>
                    <p className="text-gray-400 text-sm">
                      or click to browse files
                    </p>
                  </div>
                )}
                <input
                  ref={fileInputRef}
                  type="file"
                  onChange={handleFileSelect}
                  accept="image/*"
                  className="hidden"
                />
              </div>

              <div className="flex justify-center space-x-4">
                <button
                  onClick={handleScan}
                  disabled={loading || !selectedFile}
                  className={'px-8 py-3 rounded-lg font-medium transition ' + (loading || !selectedFile ? 'bg-gray-300 text-gray-500 cursor-not-allowed' : 'bg-green-light text-gray-900 hover:bg-green-hover shadow-sm')}
                >
                  {loading ? 'Scanning...' : 'Scan QR'}
                </button>
                <button
                  onClick={handleReset}
                  className="px-8 py-3 rounded-lg font-medium bg-white text-gray-700 border border-gray-300 hover:bg-gray-50 transition"
                >
                  Clear
                </button>
              </div>
            </div>

            {/* Scan Results */}
            {showReport && scanResult && scanResult.data && (
              <div>
                {/* Threat Level Banner */}
                <div className={'p-4 rounded-lg mb-6 border ' + (scanResult.data.threat_level === 'Safe' ? 'bg-green-50 border-green-300' : scanResult.data.threat_level === 'Medium Risk' ? 'bg-yellow-50 border-yellow-300' : scanResult.data.threat_level === 'Suspicious' ? 'bg-orange-50 border-orange-300' : 'bg-red-50 border-red-300')}>
                  <div className="flex justify-between items-center">
                    <div>
                      <h3 className={'font-bold text-lg ' + (scanResult.data.threat_level === 'Safe' ? 'text-green-800' : scanResult.data.threat_level === 'Medium Risk' ? 'text-yellow-800' : scanResult.data.threat_level === 'Suspicious' ? 'text-orange-800' : 'text-red-800')}>
                        {scanResult.data.threat_level === 'Safe' ? 'SAFE' :
                         scanResult.data.threat_level === 'Medium Risk' ? 'MEDIUM RISK' :
                         scanResult.data.threat_level === 'Suspicious' ? 'SUSPICIOUS' :
                         'DANGEROUS'}
                      </h3>
                      <p className={'text-sm mt-1 ' + (scanResult.data.threat_level === 'Safe' ? 'text-green-700' : scanResult.data.threat_level === 'Medium Risk' ? 'text-yellow-700' : scanResult.data.threat_level === 'Suspicious' ? 'text-orange-700' : 'text-red-700')}>
                        {scanResult.data.final_verdict}
                      </p>
                    </div>
                    <div className="text-right">
                      <div className="text-3xl font-bold text-gray-900">
                        {scanResult.data.security_analysis.security_score}
                      </div>
                      <div className="text-sm text-gray-500">Security Score</div>
                    </div>
                  </div>
                </div>

                {/* QR Information */}
                {scanResult.data.qr_info && (
                  <ReportCard title="QR Information">
                    <DataRow label="Content" value={scanResult.data.qr_info.content} />
                    <DataRow label="Type" value={scanResult.data.qr_info.type} />
                    <DataRow label="Category" value={scanResult.data.qr_info.category} />
                    <DataRow label="Length" value={scanResult.data.qr_info.length + ' characters'} />
                  </ReportCard>
                )}

                {/* URL Information */}
                {scanResult.data.url_info && (
                  <ReportCard title="URL Information">
                    <DataRow label="Original URL" value={scanResult.data.url_info.original_url} />
                    {scanResult.data.url_info.expanded_url !== scanResult.data.url_info.original_url && (
                      <DataRow label="Expanded URL" value={scanResult.data.url_info.expanded_url} />
                    )}
                    <DataRow label="Domain" value={scanResult.data.url_info.domain} />
                    <DataRow label="Website" value={scanResult.data.url_info.website_name} />
                    <DataRow label="SSL" value={scanResult.data.url_info.ssl_valid?.valid ? "Valid" : "Invalid"} 
                      color={scanResult.data.url_info.ssl_valid?.valid ? "text-green-600" : "text-red-600"} />
                    <DataRow label="Server" value={scanResult.data.url_info.server} />
                    <DataRow label="Redirects" value={String(scanResult.data.url_info.redirects)} />
                  </ReportCard>
                )}

                {/* Domain Information */}
                {scanResult.data.domain_info && (
                  <ReportCard title="Domain Information">
                    <DataRow label="Domain" value={scanResult.data.domain_info.domain} />
                    <DataRow label="Registrar" value={scanResult.data.domain_info.registrar} />
                    <DataRow label="Created" value={scanResult.data.domain_info.creation_date} />
                    <DataRow label="Expires" value={scanResult.data.domain_info.expiry_date} />
                    <DataRow label="Age" value={scanResult.data.domain_info.domain_age_years + ' years, ' + (scanResult.data.domain_info.domain_age_days % 365) + ' days'} />
                    <DataRow label="Country" value={scanResult.data.domain_info.registrant_country} />
                    <DataRow label="Organization" value={scanResult.data.domain_info.registrant_organization} />
                  </ReportCard>
                )}

                {/* Company Information */}
                {scanResult.data.company_info && (
                  <ReportCard title="Company Information">
                    <DataRow label="Company" value={scanResult.data.company_info.name} />
                    <DataRow label="Industry" value={scanResult.data.company_info.industry} />
                    <DataRow label="Parent" value={scanResult.data.company_info.parent_company} />
                    <DataRow label="Official Website" value={scanResult.data.company_info.official_website} />
                    <DataRow label="Reputation" value={scanResult.data.company_info.reputation} />
                  </ReportCard>
                )}

                {/* Application Information */}
                {scanResult.data.application_info && (
                  <ReportCard title="Application Information">
                    <DataRow label="Application" value={scanResult.data.application_info.name} />
                    <DataRow label="Developer" value={scanResult.data.application_info.developer} />
                    <DataRow label="Category" value={scanResult.data.application_info.category} />
                    <DataRow label="Package" value={scanResult.data.application_info.package} />
                  </ReportCard>
                )}

                {/* Product Information */}
                {scanResult.data.product_info && (
                  <ReportCard title="Product Information">
                    <DataRow label="Product" value={scanResult.data.product_info.product_name} />
                    <DataRow label="Brand" value={scanResult.data.product_info.brand} />
                    <DataRow label="Category" value={scanResult.data.product_info.category} />
                    <DataRow label="Official Site" value={scanResult.data.product_info.official_website} />
                  </ReportCard>
                )}

                {/* Brand Verification */}
                {scanResult.data.brand_verification && (
                  <ReportCard title="Brand Verification">
                    <DataRow label="Legitimate" value={scanResult.data.brand_verification.is_legitimate ? "Yes" : "No"}
                      color={scanResult.data.brand_verification.is_legitimate ? "text-green-600" : "text-red-600"} />
                    {scanResult.data.brand_verification.impersonated_brand && (
                      <DataRow label="Impersonating" value={scanResult.data.brand_verification.impersonated_brand}
                        color="text-red-600" />
                    )}
                    <DataRow label="Details" value={scanResult.data.brand_verification.verification_details} />
                  </ReportCard>
                )}

                {/* Threat Analysis */}
                {scanResult.data.threat_analysis && (
                  <ReportCard title="Threat Analysis">
                    <DataRow label="Total Threats" value={String(scanResult.data.threat_analysis.total_threats)}
                      color={scanResult.data.threat_analysis.total_threats > 0 ? "text-red-600" : "text-green-600"} />
                    <DataRow label="Phishing" value={scanResult.data.threat_analysis.has_phishing ? "Detected" : "Not Detected"}
                      color={scanResult.data.threat_analysis.has_phishing ? "text-red-600" : "text-green-600"} />
                    <DataRow label="Malware" value={scanResult.data.threat_analysis.has_malware ? "Detected" : "Not Detected"}
                      color={scanResult.data.threat_analysis.has_malware ? "text-red-600" : "text-green-600"} />
                    <DataRow label="Scam" value={scanResult.data.threat_analysis.has_scam ? "Detected" : "Not Detected"}
                      color={scanResult.data.threat_analysis.has_scam ? "text-red-600" : "text-green-600"} />
                    
                    {scanResult.data.threat_analysis.threats && scanResult.data.threat_analysis.threats.length > 0 && (
                      <div className="mt-4">
                        <h4 className="font-medium text-gray-700 mb-2">Detected Threats:</h4>
                        {scanResult.data.threat_analysis.threats.map((threat, i) => (
                          <div key={i} className={'p-3 rounded-lg mb-2 text-sm border ' + (threat.severity === 'HIGH' ? 'bg-red-50 border-red-200 text-red-700' : 'bg-yellow-50 border-yellow-200 text-yellow-700')}>
                            <span className="font-bold">{threat.type}: </span>
                            {threat.description}
                            <span className={'ml-2 px-2 py-0.5 rounded text-xs font-medium ' + (threat.severity === 'HIGH' ? 'bg-red-200 text-red-800' : 'bg-yellow-200 text-yellow-800')}>
                              {threat.severity}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </ReportCard>
                )}

                {/* Security Scores */}
                {scanResult.data.security_analysis && (
                  <ReportCard title="Security Analysis">
                    <ScoreBar label="Security Score" score={scanResult.data.security_analysis.security_score} />
                    <ScoreBar label="Trust Score" score={scanResult.data.security_analysis.trust_score} />
                    <ScoreBar label="Reputation Score" score={scanResult.data.security_analysis.reputation_score} />
                    <ScoreBar label="Threat Score" score={scanResult.data.security_analysis.threat_score} />
                    <ScoreBar label="Risk Score" score={scanResult.data.security_analysis.risk_score} />
                    <DataRow label="Risk Level" value={scanResult.data.security_analysis.risk_level}
                      color={scanResult.data.security_analysis.risk_level === 'Low' ? 'text-green-600' : scanResult.data.security_analysis.risk_level === 'Medium' ? 'text-yellow-600' : 'text-red-600'} />
                  </ReportCard>
                )}

                {/* Recommendations */}
                {scanResult.data.recommendations && (
                  <ReportCard title="Recommendations">
                    <ul className="space-y-2">
                      {scanResult.data.recommendations.map((rec, i) => (
                        <li key={i} className="flex items-start">
                          <span className="text-gray-400 mr-2">-</span>
                          <span className="text-gray-700">{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </ReportCard>
                )}

                {/* Download Report Button */}
                <div className="glass-card p-6 mb-6 text-center">
                  <p className="text-gray-600 mb-4">
                    Scan ID: #{scanId}
                  </p>
                  <div className="flex justify-center space-x-4">
                    <button
                      onClick={downloadPdfReport}
                      className="px-6 py-3 bg-green-light text-gray-900 rounded-lg font-medium hover:bg-green-hover transition shadow-sm"
                    >
                      Download PDF Report
                    </button>
                    <button
                      onClick={handleReset}
                      className="px-6 py-3 bg-white text-gray-700 border border-gray-300 rounded-lg font-medium hover:bg-gray-50 transition"
                    >
                      Scan New QR
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* No results message */}
            {!showReport && (
              <div className="glass-card p-12 text-center">
                <div className="text-gray-400 mb-3">
                  <svg className="mx-auto h-16 w-16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" />
                  </svg>
                </div>
                <p className="text-gray-500 text-lg">
                  Upload a QR code image and click Scan to analyze
                </p>
                <p className="text-gray-400 text-sm mt-2">
                  Get complete intelligence report including URL, domain, company, threats and more
                </p>
              </div>
            )}
          </div>
        )}

        {/* DASHBOARD TAB */}
        {activeTab === 'dashboard' && (
          <div>
            <h2 className="text-xl font-semibold text-gray-900 mb-6">Dashboard</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
              <div className="glass-card p-6 text-center">
                <p className="text-3xl font-bold text-gray-900">{dashboard?.total_scans || 0}</p>
                <p className="text-sm text-gray-500 mt-1">Total Scans</p>
              </div>
              <div className="glass-card p-6 text-center">
                <p className="text-3xl font-bold text-green-600">{dashboard?.safe_count || 0}</p>
                <p className="text-sm text-gray-500 mt-1">Safe QR Codes</p>
              </div>
              <div className="glass-card p-6 text-center">
                <p className="text-3xl font-bold text-yellow-600">{dashboard?.suspicious_count || 0}</p>
                <p className="text-sm text-gray-500 mt-1">Suspicious QR Codes</p>
              </div>
              <div className="glass-card p-6 text-center">
                <p className="text-3xl font-bold text-red-600">{dashboard?.dangerous_count || 0}</p>
                <p className="text-sm text-gray-500 mt-1">Dangerous QR Codes</p>
              </div>
            </div>

            <div className="glass-card p-6 mb-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Domains</h3>
              {dashboard?.top_domains && dashboard.top_domains.length > 0 ? (
                <div className="space-y-3">
                  {dashboard.top_domains.map((item, i) => (
                    <div key={i} className="flex justify-between items-center py-2 border-b border-gray-100 last:border-0">
                      <span className="text-gray-700">{item.domain}</span>
                      <span className="text-gray-500 text-sm">{item.count} scans</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-400 text-center py-4">No domains scanned yet</p>
              )}
            </div>

            <div className="glass-card p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h3>
              {dashboard?.recent_scans && dashboard.recent_scans.length > 0 ? (
                <div className="space-y-3">
                  {[...dashboard.recent_scans].reverse().map((scan, i) => (
                    <div key={i} className="flex justify-between items-center py-2 border-b border-gray-100 last:border-0">
                      <span className="text-gray-700 text-sm truncate max-w-xs">
                        {scan.qr_data?.substring(0, 50)}...
                      </span>
                      <span className={'px-2 py-1 rounded text-xs font-medium border ' + (scan.threat_level === 'Safe' ? 'bg-green-100 text-green-800 border-green-300' : scan.threat_level === 'Suspicious' ? 'bg-orange-100 text-orange-800 border-orange-300' : 'bg-red-100 text-red-800 border-red-300')}>
                        {scan.threat_level}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-400 text-center py-4">No recent activity</p>
              )}
            </div>
          </div>
        )}

        {/* HISTORY TAB */}
        {activeTab === 'history' && (
          <div>
            <h2 className="text-xl font-semibold text-gray-900 mb-6">Scan History</h2>
            <div className="glass-card p-6">
              {history && history.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200">
                        <th className="text-left py-3 px-4 text-gray-600 font-medium text-sm">ID</th>
                        <th className="text-left py-3 px-4 text-gray-600 font-medium text-sm">Content</th>
                        <th className="text-left py-3 px-4 text-gray-600 font-medium text-sm">Date</th>
                        <th className="text-left py-3 px-4 text-gray-600 font-medium text-sm">Score</th>
                        <th className="text-left py-3 px-4 text-gray-600 font-medium text-sm">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...history].reverse().map((scan, i) => (
                        <tr key={i} className="border-b border-gray-100 hover:bg-gray-50">
                          <td className="py-3 px-4 text-gray-700">{scan.id}</td>
                          <td className="py-3 px-4 text-gray-700 text-sm max-w-xs truncate">
                            {scan.qr_data?.substring(0, 60)}
                          </td>
                          <td className="py-3 px-4 text-gray-500 text-sm">
                            {scan.timestamp ? new Date(scan.timestamp).toLocaleDateString() : 'N/A'}
                          </td>
                          <td className="py-3 px-4">
                            <span className={getScoreColor(scan.security_score)}>
                              {scan.security_score}/100
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            <span className={'px-2 py-1 rounded text-xs font-medium border ' + getThreatBadge(scan.threat_level)}>
                              {scan.threat_level}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-gray-400 text-center py-8">No scan history yet</p>
              )}
            </div>
          </div>
        )}

      </main>

      {/* Footer */}
      <footer className="bg-green-light border-t border-gray-200 mt-8">
        <div className="max-w-7xl mx-auto px-4 py-4 text-center">
          <p className="text-gray-600 text-sm">Developed By Zakia Rani</p>
        </div>
      </footer>
    </div>
  );
}

export default App;
