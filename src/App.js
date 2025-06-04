import React, { useState, useEffect, useRef } from 'react';
import { Shield, AlertCircle, CheckCircle2, Mail, Globe, Zap, Eye, EyeOff, TrendingUp, Lock, Unlock, Activity, FileWarning, Link2, Ban, Radar, Wifi, WifiOff, Cpu, Terminal, Code, ArrowRight, X, Info, ChevronDown, ChevronUp, ExternalLink, Copy, CheckCheck } from 'lucide-react';

const InteractiveCyberSecurityAnalyzer = () => {
  const [mode, setMode] = useState('url');
  const [input, setInput] = useState('');
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showDetails, setShowDetails] = useState(true);
  const [realtimeScore, setRealtimeScore] = useState(0);
  const [scanningStep, setScanningStep] = useState('');
  const [particles, setParticles] = useState([]);
  const [hoveredThreat, setHoveredThreat] = useState(null);
  const [expandedThreat, setExpandedThreat] = useState(null);
  const [terminalLogs, setTerminalLogs] = useState([]);
  const [showTerminal, setShowTerminal] = useState(false);
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [pulseEffect, setPulseEffect] = useState(false);
  const [threatRadar, setThreatRadar] = useState({ angle: 0, threats: [] });
  const terminalRef = useRef(null);

  // Particle effect system
  useEffect(() => {
    const interval = setInterval(() => {
      setParticles(prev => {
        const newParticles = prev
          .map(p => ({ 
            ...p, 
            y: p.y - p.speed,
            opacity: p.opacity - 0.01,
            x: p.x + (Math.random() - 0.5) * 2
          }))
          .filter(p => p.opacity > 0);

        if (Math.random() > 0.7 && newParticles.length < 50) {
          newParticles.push({
            id: Date.now() + Math.random(),
            x: Math.random() * window.innerWidth,
            y: window.innerHeight,
            speed: 1 + Math.random() * 3,
            size: 1 + Math.random() * 3,
            opacity: 0.5,
            color: ['blue', 'purple', 'cyan'][Math.floor(Math.random() * 3)]
          });
        }

        return newParticles;
      });
    }, 50);

    return () => clearInterval(interval);
  }, []);

  // Threat radar animation
  useEffect(() => {
    const radarInterval = setInterval(() => {
      setThreatRadar(prev => ({
        ...prev,
        angle: (prev.angle + 2) % 360
      }));
    }, 30);

    return () => clearInterval(radarInterval);
  }, []);

  // Terminal auto-scroll
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLogs]);

  const addTerminalLog = (message, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = {
      id: Date.now() + Math.random(),
      timestamp,
      message,
      type // info, success, warning, error
    };
    setTerminalLogs(prev => [...prev.slice(-50), logEntry]);
  };

  // Enhanced URL Analysis with interactive feedback
  const performURLAnalysis = async (url) => {
    setLoading(true);
    setRealtimeScore(0);
    setPulseEffect(true);
    setShowTerminal(true);
    setTerminalLogs([]);
    
    const scanSteps = [
      'Initializing security scanners...',
      'Resolving DNS records...',
      'Checking SSL certificate...',
      'Analyzing domain reputation...',
      'Scanning for malicious patterns...',
      'Querying threat intelligence database...',
      'Calculating risk score...'
    ];

    addTerminalLog('Starting URL security analysis', 'info');
    addTerminalLog(`Target: ${url}`, 'info');

    let currentStep = 0;
    const stepInterval = setInterval(() => {
      if (currentStep < scanSteps.length) {
        setScanningStep(scanSteps[currentStep]);
        addTerminalLog(scanSteps[currentStep], 'info');
        currentStep++;
      }
    }, 300);

    // Simulate real-time scoring with easing
    let targetScore = 0;
    const scoreInterval = setInterval(() => {
      setRealtimeScore(prev => {
        const diff = targetScore - prev;
        return prev + diff * 0.1;
      });
    }, 50);

    await new Promise(resolve => setTimeout(resolve, 2500));
    clearInterval(stepInterval);

    const threats = [];
    const features = {
      protocol: { safe: false, detail: '', icon: '🔒' },
      domain: { safe: true, detail: '', icon: '🌐' },
      path: { safe: true, detail: '', icon: '📁' },
      params: { safe: true, detail: '', icon: '🔍' },
      reputation: { safe: true, detail: '', icon: '⭐' }
    };
    
    let threatLevel = 0;

    // Protocol Analysis
    if (!url.startsWith('https://')) {
      features.protocol.safe = false;
      features.protocol.detail = 'Insecure HTTP protocol';
      threats.push({
        id: 'prot-1',
        severity: 'high',
        category: 'Protocol',
        description: 'Non-encrypted connection vulnerable to MITM attacks',
        mitigation: 'Always use HTTPS for sensitive data',
        details: 'HTTP traffic can be intercepted and modified by attackers',
        references: ['OWASP Transport Layer Protection', 'RFC 2818']
      });
      threatLevel += 30;
      addTerminalLog('⚠️ WARNING: Insecure HTTP protocol detected', 'warning');
    } else {
      features.protocol.safe = true;
      features.protocol.detail = 'Secure HTTPS protocol';
      addTerminalLog('✓ Secure HTTPS protocol confirmed', 'success');
    }

    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      
      // IP Address Check
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
        features.domain.safe = false;
        features.domain.detail = 'Direct IP address';
        threats.push({
          id: 'dom-1',
          severity: 'high',
          category: 'Domain',
          description: 'IP addresses often used to bypass domain reputation',
          mitigation: 'Verify IP ownership before proceeding',
          details: 'Legitimate services rarely use direct IP addresses',
          references: ['MITRE ATT&CK T1564']
        });
        threatLevel += 40;
        addTerminalLog(`⚠️ Suspicious: Direct IP address ${domain}`, 'error');
      }

      // Advanced pattern detection
      const suspiciousPatterns = [
        { pattern: /phishing|fraud|scam/i, weight: 50, name: 'Phishing keywords' },
        { pattern: /[0-9]{4,}/, weight: 15, name: 'Excessive numbers' },
        { pattern: /-{3,}/, weight: 20, name: 'Multiple hyphens' },
        { pattern: /xn--/, weight: 35, name: 'Punycode domain' }
      ];

      suspiciousPatterns.forEach(({ pattern, weight, name }) => {
        if (pattern.test(url)) {
          threatLevel += weight;
          addTerminalLog(`⚠️ Detected: ${name}`, 'warning');
        }
      });

    } catch (e) {
      features.domain.safe = false;
      features.domain.detail = 'Invalid URL format';
      threatLevel += 60;
      addTerminalLog('❌ ERROR: Invalid URL format', 'error');
    }

    targetScore = Math.min(threatLevel, 100);
    
    // Add detected threats to radar
    const radarThreats = threats.map((t, i) => ({
      id: t.id,
      angle: (i * 60) + Math.random() * 30,
      distance: 50 + Math.random() * 100,
      severity: t.severity
    }));
    
    setThreatRadar(prev => ({ ...prev, threats: radarThreats }));

    await new Promise(resolve => setTimeout(resolve, 500));
    clearInterval(scoreInterval);
    setRealtimeScore(targetScore);

    addTerminalLog(`Analysis complete. Risk score: ${targetScore}%`, targetScore > 70 ? 'error' : targetScore > 40 ? 'warning' : 'success');

    setAnalysis({
      type: 'url',
      input: url,
      score: targetScore,
      status: targetScore > 70 ? 'critical' : targetScore > 40 ? 'warning' : 'safe',
      features,
      threats,
      recommendations: generateRecommendations(threats),
      timestamp: new Date().toISOString()
    });
    
    setLoading(false);
    setScanningStep('');
    setPulseEffect(false);
  };

  // Enhanced Email Analysis
  const performEmailAnalysis = async (content) => {
    setLoading(true);
    setRealtimeScore(0);
    setPulseEffect(true);
    setShowTerminal(true);
    setTerminalLogs([]);
    
    addTerminalLog('Initializing email security scanner', 'info');
    addTerminalLog('Loading phishing detection models...', 'info');

    const scanSteps = [
      'Parsing email headers...',
      'Analyzing sender reputation...',
      'Scanning for social engineering tactics...',
      'Checking embedded links...',
      'Running sentiment analysis...',
      'Comparing against phishing database...'
    ];

    let currentStep = 0;
    const stepInterval = setInterval(() => {
      if (currentStep < scanSteps.length) {
        setScanningStep(scanSteps[currentStep]);
        addTerminalLog(scanSteps[currentStep], 'info');
        currentStep++;
      }
    }, 400);

    await new Promise(resolve => setTimeout(resolve, 3000));
    clearInterval(stepInterval);

    const threats = [];
    const patterns = {
      sender: { suspicious: false, details: [], icon: '📧' },
      content: { suspicious: false, details: [], icon: '📝' },
      links: { suspicious: false, details: [], icon: '🔗' },
      attachments: { suspicious: false, details: [], icon: '📎' },
      language: { suspicious: false, details: [], icon: '🔤' }
    };
    
    let threatLevel = 0;

    // Advanced pattern matching with visual feedback
    const socialEngineering = {
      urgency: {
        patterns: [/act now/i, /urgent/i, /immediate/i, /expires/i],
        message: 'Creates false sense of urgency',
        icon: '⏰'
      },
      authority: {
        patterns: [/suspended/i, /locked/i, /security team/i],
        message: 'Impersonates authority figures',
        icon: '👮'
      },
      fear: {
        patterns: [/hacked/i, /breach/i, /compromised/i],
        message: 'Uses fear to manipulate',
        icon: '😱'
      },
      greed: {
        patterns: [/won/i, /prize/i, /million/i, /free/i],
        message: 'Appeals to greed',
        icon: '💰'
      }
    };

    Object.entries(socialEngineering).forEach(([tactic, config]) => {
      const matches = config.patterns.filter(p => p.test(content));
      if (matches.length > 0) {
        patterns.content.suspicious = true;
        patterns.content.details.push(`${config.icon} ${tactic} tactics`);
        threats.push({
          id: `se-${tactic}`,
          severity: matches.length > 2 ? 'high' : 'medium',
          category: 'Social Engineering',
          description: config.message,
          mitigation: 'Be skeptical of emotional manipulation',
          details: `Found ${matches.length} ${tactic} indicators`,
          icon: config.icon
        });
        threatLevel += matches.length * 15;
        addTerminalLog(`⚠️ Detected ${tactic} manipulation tactics`, 'warning');
      }
    });

    const finalScore = Math.min(threatLevel, 100);
    setRealtimeScore(finalScore);

    addTerminalLog(`Email analysis complete. Phishing score: ${finalScore}%`, 
      finalScore > 70 ? 'error' : finalScore > 40 ? 'warning' : 'success');

    setAnalysis({
      type: 'email',
      input: content.substring(0, 100) + '...',
      score: finalScore,
      status: finalScore > 70 ? 'critical' : finalScore > 40 ? 'warning' : 'safe',
      patterns,
      threats,
      recommendations: generateRecommendations(threats),
      timestamp: new Date().toISOString()
    });
    
    setLoading(false);
    setScanningStep('');
    setPulseEffect(false);
  };

  const generateRecommendations = (threats) => {
    const recs = [];
    
    if (threats.some(t => t.severity === 'critical')) {
      recs.push('⛔ Do not proceed - Critical threats detected');
    }
    if (threats.some(t => t.severity === 'high')) {
      recs.push('🚨 High risk - Exercise extreme caution');
    }
    if (threats.length === 0) {
      recs.push('✅ No immediate threats detected');
      recs.push('👀 Still verify sender and context');
    }
    
    return recs;
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedUrl(true);
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'from-red-600 to-red-800 shadow-red-500/50',
      high: 'from-orange-600 to-orange-800 shadow-orange-500/50',
      medium: 'from-yellow-600 to-yellow-800 shadow-yellow-500/50',
      low: 'from-blue-600 to-blue-800 shadow-blue-500/50'
    };
    return colors[severity] || colors.low;
  };

  const getTerminalLogColor = (type) => {
    switch(type) {
      case 'error': return 'text-red-400';
      case 'warning': return 'text-yellow-400';
      case 'success': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="min-h-screen bg-black text-white relative overflow-hidden">
      {/* Animated Particles */}
      {particles.map(p => (
        <div
          key={p.id}
          className={`absolute w-${p.size} h-${p.size} bg-${p.color}-500 rounded-full pointer-events-none`}
          style={{
            left: `${p.x}px`,
            top: `${p.y}px`,
            opacity: p.opacity,
            width: `${p.size}px`,
            height: `${p.size}px`,
            backgroundColor: p.color === 'blue' ? '#3B82F6' : p.color === 'purple' ? '#9333EA' : '#06B6D4'
          }}
        />
      ))}

      {/* Animated Grid */}
      <div className="absolute inset-0 bg-grid-pattern opacity-5"></div>

      {/* Scanning Effect Overlay */}
      {loading && (
        <div className="fixed inset-0 pointer-events-none z-50">
          <div className="scan-line"></div>
        </div>
      )}

      <div className="relative z-10 container mx-auto px-4 py-8 max-w-7xl">
        {/* Header with Pulse Effect */}
        <header className="text-center mb-12 relative">
          <div className={`inline-flex items-center justify-center p-4 bg-gradient-to-r from-blue-600 to-purple-600 rounded-2xl mb-6 ${pulseEffect ? 'animate-pulse' : ''}`}>
            <Shield className="w-12 h-12" />
          </div>
          <h1 className="text-6xl font-bold mb-4 bg-gradient-to-r from-blue-400 via-purple-400 to-pink-400 bg-clip-text text-transparent animate-gradient">
            Cyber Threat Intelligence
          </h1>
          <p className="text-gray-400 text-xl">Advanced AI Security Analysis Platform</p>
          
          {/* Live Status Indicators */}
          <div className="flex justify-center gap-6 mt-6">
            <div className="flex items-center gap-2 text-sm">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              <span className="text-gray-400">Systems Online</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Wifi className="w-4 h-4 text-blue-400 animate-pulse" />
              <span className="text-gray-400">Threat Intel Connected</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Activity className="w-4 h-4 text-purple-400" />
              <span className="text-gray-400">ML Models Active</span>
            </div>
          </div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Analysis Panel */}
          <div className="lg:col-span-2 space-y-6">
            {/* Mode Selector with Hover Effects */}
            <div className="flex justify-center">
              <div className="bg-gray-900/80 backdrop-blur-xl p-1 rounded-2xl flex gap-1 border border-gray-800">
                <button
                  onClick={() => setMode('url')}
                  onMouseEnter={() => addTerminalLog('Hover: URL Scanner mode', 'info')}
                  className={`px-8 py-4 rounded-xl font-medium transition-all duration-300 flex items-center gap-3 ${
                    mode === 'url'
                      ? 'bg-gradient-to-r from-blue-600 to-blue-700 text-white shadow-lg shadow-blue-500/25 scale-105'
                      : 'text-gray-400 hover:text-white hover:bg-gray-800 hover:scale-105'
                  }`}
                >
                  <Globe className={`w-5 h-5 ${mode === 'url' ? 'animate-spin-slow' : ''}`} />
                  URL Scanner
                </button>
                <button
                  onClick={() => setMode('email')}
                  onMouseEnter={() => addTerminalLog('Hover: Email Analyzer mode', 'info')}
                  className={`px-8 py-4 rounded-xl font-medium transition-all duration-300 flex items-center gap-3 ${
                    mode === 'email'
                      ? 'bg-gradient-to-r from-purple-600 to-purple-700 text-white shadow-lg shadow-purple-500/25 scale-105'
                      : 'text-gray-400 hover:text-white hover:bg-gray-800 hover:scale-105'
                  }`}
                >
                  <Mail className={`w-5 h-5 ${mode === 'email' ? 'animate-bounce' : ''}`} />
                  Email Analyzer
                </button>
              </div>
            </div>

            {/* Input Section with Interactive Elements */}
            <div className="bg-gray-900/50 backdrop-blur-xl rounded-2xl p-8 border border-gray-800 hover:border-gray-700 transition-all duration-300">
              {mode === 'url' ? (
                <>
                  <label className="block text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
                    <Radar className="w-4 h-4 text-blue-400 animate-pulse" />
                    Enter URL for Deep Security Analysis
                  </label>
                  <div className="relative">
                    <input
                      type="text"
                      value={input}
                      onChange={(e) => {
                        setInput(e.target.value);
                        if (e.target.value.length > 0) {
                          addTerminalLog(`Input detected: ${e.target.value.slice(-1)}`, 'info');
                        }
                      }}
                      placeholder="https://suspicious-site.com/verify-account"
                      className="w-full px-5 py-4 pr-24 bg-black/50 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all"
                    />
                    {input && (
                      <button
                        onClick={() => copyToClipboard(input)}
                        className="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-gray-400 hover:text-white transition-colors"
                      >
                        {copiedUrl ? <CheckCheck className="w-5 h-5 text-green-500" /> : <Copy className="w-5 h-5" />}
                      </button>
                    )}
                  </div>
                  
                  <button
                    onClick={() => performURLAnalysis(input)}
                    disabled={!input || loading}
                    className={`mt-4 w-full px-8 py-4 rounded-xl font-medium transition-all duration-300 flex items-center justify-center gap-3 group ${
                      loading
                        ? 'bg-gray-700 cursor-wait'
                        : 'bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 shadow-lg shadow-blue-500/25 hover:shadow-blue-500/40 hover:scale-[1.02]'
                    } disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100`}
                  >
                    {loading ? (
                      <>
                        <Activity className="w-5 h-5 animate-spin" />
                        <span className="animate-pulse">{scanningStep || 'Analyzing...'}</span>
                      </>
                    ) : (
                      <>
                        <Zap className="w-5 h-5 group-hover:animate-bounce" />
                        Start Security Scan
                        <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                      </>
                    )}
                  </button>
                  
                  {/* Interactive Examples */}
                  <div className="mt-6 space-y-2">
                    <p className="text-xs text-gray-500 uppercase tracking-wider">Quick Examples</p>
                    <div className="grid grid-cols-3 gap-2">
                      <button
                        onClick={() => {
                          setInput('http://192.168.1.1/admin/verify-account.php');
                          addTerminalLog('Loaded malicious URL example', 'warning');
                        }}
                        className="group relative px-3 py-2 bg-red-900/20 text-red-400 rounded-lg hover:bg-red-900/40 transition-all duration-300 overflow-hidden"
                      >
                        <span className="relative z-10 text-sm">Malicious</span>
                        <div className="absolute inset-0 bg-red-600 opacity-0 group-hover:opacity-20 transition-opacity"></div>
                      </button>
                      <button
                        onClick={() => {
                          setInput('https://github.com/anthropics/claude');
                          addTerminalLog('Loaded safe URL example', 'success');
                        }}
                        className="group relative px-3 py-2 bg-green-900/20 text-green-400 rounded-lg hover:bg-green-900/40 transition-all duration-300 overflow-hidden"
                      >
                        <span className="relative z-10 text-sm">Safe</span>
                        <div className="absolute inset-0 bg-green-600 opacity-0 group-hover:opacity-20 transition-opacity"></div>
                      </button>
                      <button
                        onClick={() => {
                          setInput('http://bit.ly/win-prize-now');
                          addTerminalLog('Loaded suspicious URL example', 'warning');
                        }}
                        className="group relative px-3 py-2 bg-yellow-900/20 text-yellow-400 rounded-lg hover:bg-yellow-900/40 transition-all duration-300 overflow-hidden"
                      >
                        <span className="relative z-10 text-sm">Suspicious</span>
                        <div className="absolute inset-0 bg-yellow-600 opacity-0 group-hover:opacity-20 transition-opacity"></div>
                      </button>
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <label className="block text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
                    <FileWarning className="w-4 h-4 text-purple-400 animate-pulse" />
                    Paste Email Content for Phishing Detection
                  </label>
                  <textarea
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder="Paste suspicious email content here..."
                    className="w-full px-5 py-4 bg-black/50 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 transition-all h-40 resize-none"
                  />
                  <button
                    onClick={() => performEmailAnalysis(input)}
                    disabled={!input || loading}
                    className={`mt-4 w-full px-8 py-4 rounded-xl font-medium transition-all duration-300 flex items-center justify-center gap-3 group ${
                      loading
                        ? 'bg-gray-700 cursor-wait'
                        : 'bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 shadow-lg shadow-purple-500/25 hover:shadow-purple-500/40 hover:scale-[1.02]'
                    } disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100`}
                  >
                    {loading ? (
                      <>
                        <Activity className="w-5 h-5 animate-spin" />
                        <span className="animate-pulse">{scanningStep || 'Analyzing...'}</span>
                      </>
                    ) : (
                      <>
                        <Zap className="w-5 h-5 group-hover:animate-bounce" />
                        Analyze Email
                        <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                      </>
                    )}
                  </button>
                </>
              )}
            </div>

            {/* Interactive Results */}
            {analysis && !loading && (
              <div className="space-y-6">
                {/* Main Risk Card with Hover Effects */}
                <div 
                  className={`relative bg-gradient-to-br ${
                    analysis.status === 'critical' ? 'from-red-900/50 to-red-800/50' :
                    analysis.status === 'warning' ? 'from-yellow-900/50 to-orange-800/50' :
                    'from-green-900/50 to-green-800/50'
                  } rounded-2xl p-8 border ${
                    analysis.status === 'critical' ? 'border-red-700' :
                    analysis.status === 'warning' ? 'border-yellow-700' :
                    'border-green-700'
                  } overflow-hidden group hover:scale-[1.01] transition-transform duration-300`}
                >
                  {/* Animated Background Pattern */}
                  <div className="absolute inset-0 opacity-10">
                    <div className="absolute inset-0 bg-circuit-pattern animate-slide"></div>
                  </div>
                  
                  <div className="relative z-10">
                    <div className="flex items-center justify-between mb-6">
                      <div>
                        <h3 className="text-2xl font-bold mb-2 flex items-center gap-3">
                          {analysis.status === 'critical' ? <AlertCircle className="w-8 h-8 text-red-400 animate-pulse" /> :
                           analysis.status === 'warning' ? <AlertCircle className="w-8 h-8 text-yellow-400" /> :
                           <CheckCircle2 className="w-8 h-8 text-green-400" />}
                          Threat Assessment
                        </h3>
                        <p className="text-gray-300">
                          Scan completed at {new Date(analysis.timestamp).toLocaleTimeString()}
                        </p>
                      </div>
                      <div className="text-right">
                        <div className="text-6xl font-bold mb-2 tabular-nums">
                          {analysis.score}%
                        </div>
                        <div className="text-lg font-medium uppercase tracking-wider">
                          {analysis.status} Risk
                        </div>
                      </div>
                    </div>
                    
                    {/* Interactive Progress Bar */}
                    <div className="relative h-6 bg-black/30 rounded-full overflow-hidden group-hover:h-8 transition-all duration-300">
                      <div
                        className={`h-full rounded-full transition-all duration-1000 ease-out flex items-center justify-end pr-3 ${
                          analysis.status === 'critical' ? 'bg-gradient-to-r from-red-600 to-red-500' :
                          analysis.status === 'warning' ? 'bg-gradient-to-r from-yellow-600 to-orange-500' :
                          'bg-gradient-to-r from-green-600 to-green-500'
                        }`}
                        style={{ width: `${analysis.score}%` }}
                      >
                        <span className="text-xs font-medium opacity-0 group-hover:opacity-100 transition-opacity">
                          {analysis.score}% Risk
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Interactive Threat Cards */}
                {analysis.threats.length > 0 && (
                  <div className="space-y-4">
                    <h3 className="text-xl font-bold flex items-center gap-2">
                      <FileWarning className="w-6 h-6 text-red-500" />
                      Detected Threats ({analysis.threats.length})
                    </h3>
                    
                    <div className="grid gap-3">
                      {analysis.threats.map((threat) => (
                        <div
                          key={threat.id}
                          onMouseEnter={() => setHoveredThreat(threat.id)}
                          onMouseLeave={() => setHoveredThreat(null)}
                          onClick={() => setExpandedThreat(expandedThreat === threat.id ? null : threat.id)}
                          className={`relative p-5 rounded-xl border bg-gradient-to-br ${getSeverityColor(threat.severity)} 
                            cursor-pointer transform transition-all duration-300 
                            ${hoveredThreat === threat.id ? 'scale-[1.02] shadow-2xl' : 'shadow-lg'}
                            ${expandedThreat === threat.id ? 'ring-2 ring-white/20' : ''}`}
                        >
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center gap-3">
                              <span className="text-2xl">{threat.icon || '⚠️'}</span>
                              <div>
                                <h4 className="font-bold text-lg">{threat.category}</h4>
                                <span className={`text-xs px-3 py-1 rounded-full bg-black/30 inline-block mt-1`}>
                                  {threat.severity.toUpperCase()} SEVERITY
                                </span>
                              </div>
                            </div>
                            <ChevronDown className={`w-5 h-5 transition-transform ${expandedThreat === threat.id ? 'rotate-180' : ''}`} />
                          </div>
                          
                          <p className="text-sm mb-2">{threat.description}</p>
                          
                          {expandedThreat === threat.id && (
                            <div className="mt-4 pt-4 border-t border-white/10 space-y-3 animate-fadeIn">
                              <div>
                                <p className="text-xs uppercase tracking-wider opacity-70 mb-1">Details</p>
                                <p className="text-sm">{threat.details}</p>
                              </div>
                              <div>
                                <p className="text-xs uppercase tracking-wider opacity-70 mb-1">Mitigation</p>
                                <p className="text-sm">💡 {threat.mitigation}</p>
                              </div>
                              {threat.references && (
                                <div>
                                  <p className="text-xs uppercase tracking-wider opacity-70 mb-1">References</p>
                                  <div className="flex gap-2 flex-wrap">
                                    {threat.references.map((ref, i) => (
                                      <span key={i} className="text-xs px-2 py-1 bg-black/20 rounded">
                                        {ref}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Right Sidebar - Live Monitoring */}
          <div className="space-y-6">
            {/* Threat Radar */}
            <div className="bg-gray-900/50 backdrop-blur-xl rounded-2xl p-6 border border-gray-800">
              <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                <Radar className="w-5 h-5 text-blue-400" />
                Live Threat Radar
              </h3>
              <div className="relative w-full aspect-square">
                <svg className="w-full h-full" viewBox="0 0 200 200">
                  {/* Radar circles */}
                  {[1, 2, 3, 4].map(i => (
                    <circle
                      key={i}
                      cx="100"
                      cy="100"
                      r={i * 20}
                      fill="none"
                      stroke="rgba(59, 130, 246, 0.2)"
                      strokeWidth="1"
                    />
                  ))}
                  
                  {/* Radar sweep */}
                  <line
                    x1="100"
                    y1="100"
                    x2={100 + 80 * Math.cos((threatRadar.angle - 90) * Math.PI / 180)}
                    y2={100 + 80 * Math.sin((threatRadar.angle - 90) * Math.PI / 180)}
                    stroke="rgba(59, 130, 246, 0.6)"
                    strokeWidth="2"
                    className="radar-sweep"
                  />
                  
                  {/* Threat dots */}
                  {threatRadar.threats.map(threat => (
                    <circle
                      key={threat.id}
                      cx={100 + threat.distance * Math.cos((threat.angle - 90) * Math.PI / 180) / 2}
                      cy={100 + threat.distance * Math.sin((threat.angle - 90) * Math.PI / 180) / 2}
                      r="4"
                      fill={threat.severity === 'critical' ? '#EF4444' : 
                            threat.severity === 'high' ? '#F59E0B' : '#3B82F6'}
                      className="animate-pulse"
                    />
                  ))}
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-blue-400">
                      {loading ? 'SCANNING' : threatRadar.threats.length}
                    </div>
                    <div className="text-xs text-gray-500">
                      {loading ? '' : 'Threats Detected'}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Live Terminal */}
            <div className="bg-gray-900/50 backdrop-blur-xl rounded-2xl border border-gray-800 overflow-hidden">
              <div className="flex items-center justify-between p-4 border-b border-gray-800">
                <div className="flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-green-400" />
                  <h3 className="font-bold">Security Terminal</h3>
                </div>
                <button
                  onClick={() => setShowTerminal(!showTerminal)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  {showTerminal ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                </button>
              </div>
              
              {showTerminal && (
                <div 
                  ref={terminalRef}
                  className="p-4 h-64 overflow-y-auto font-mono text-sm space-y-1 bg-black/50"
                >
                  {terminalLogs.map(log => (
                    <div key={log.id} className={`${getTerminalLogColor(log.type)} animate-fadeIn`}>
                      <span className="text-gray-600">[{log.timestamp}]</span> {log.message}
                    </div>
                  ))}
                  {terminalLogs.length === 0 && (
                    <div className="text-gray-600">Waiting for input...</div>
                  )}
                </div>
              )}
            </div>

            {/* Quick Stats */}
            <div className="bg-gray-900/50 backdrop-blur-xl rounded-2xl p-6 border border-gray-800">
              <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-purple-400" />
                Session Statistics
              </h3>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">URLs Scanned</span>
                  <span className="font-bold">0</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Threats Blocked</span>
                  <span className="font-bold text-red-400">0</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Safe Sites</span>
                  <span className="font-bold text-green-400">0</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Active Time</span>
                  <span className="font-bold">00:00</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <style jsx>{`
        .bg-grid-pattern {
          background-image: 
            linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
          background-size: 50px 50px;
        }
        
        .bg-circuit-pattern {
          background-image: url("data:image/svg+xml,%3Csvg width='100' height='100' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M10 10h80v80h-80z' fill='none' stroke='%23444' stroke-width='0.5'/%3E%3C/svg%3E");
          background-size: 100px 100px;
        }
        
        @keyframes slide {
          0% { transform: translateX(0); }
          100% { transform: translateX(100px); }
        }
        
        .animate-slide {
          animation: slide 20s linear infinite;
        }
        
        @keyframes gradient {
          0%, 100% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
        }
        
        .animate-gradient {
          background-size: 200% 200%;
          animation: gradient 6s ease infinite;
        }
        
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        
        .animate-fadeIn {
          animation: fadeIn 0.3s ease-out;
        }
        
        .animate-spin-slow {
          animation: spin 4s linear infinite;
        }
        
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        
        .scan-line {
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          height: 4px;
          background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.8), transparent);
          animation: scan 2s linear infinite;
        }
        
        @keyframes scan {
          0% { transform: translateY(0); }
          100% { transform: translateY(100vh); }
        }
        
        .radar-sweep {
          transform-origin: 100px 100px;
          opacity: 0.8;
          filter: drop-shadow(0 0 10px rgba(59, 130, 246, 0.8));
        }
      `}</style>
    </div>
  );
};

export default InteractiveCyberSecurityAnalyzer;