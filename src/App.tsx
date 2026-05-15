import { useState, useEffect, useMemo, useRef } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Globe, 
  Server, 
  Trash2, 
  Plus, 
  Activity, 
  Lock, 
  Unlock,
  AlertTriangle,
  History,
  Play,
  Pause,
  RefreshCw
} from 'lucide-react';

// Konfigurasi Jenis Protokol
const PROTOCOLS = [
  { id: 'HTTP', port: 80, color: 'bg-blue-400', risk: 'Low' },
  { id: 'HTTPS', port: 443, color: 'bg-green-400', risk: 'Low' },
  { id: 'SSH', port: 22, color: 'bg-purple-400', risk: 'Medium' },
  { id: 'FTP', port: 21, color: 'bg-yellow-400', risk: 'Medium' },
  { id: 'RDP', port: 3389, color: 'bg-orange-400', risk: 'High' },
  { id: 'ICMP', port: 0, color: 'bg-gray-400', risk: 'Low' },
  { id: 'MALWARE', port: 666, color: 'bg-red-500', risk: 'Critical' },
] as const;

const ALERT_TYPES = [
  'Malware Detected',
  'DDoS Attack',
  'SSH Brute Force',
  'SQL Injection',
  'Port Scanning',
  'Unauthorized Access',
  'Suspicious Traffic',
] as const;

type Action = 'ALLOW' | 'BLOCK';
type FirewallMode = 'BLACKLIST' | 'WHITELIST';
type Risk = 'Low' | 'Medium' | 'High' | 'Critical';
type PacketStatus = 'PENDING' | Action;
type AlertType = typeof ALERT_TYPES[number];

type Rule = {
  id: number;
  protocol: string;
  sourceIp: string;
  action: Action;
  description?: string;
};

type Packet = {
  id: number;
  protocol: string;
  color: string;
  sourceIp: string;
  x: number;
  status: PacketStatus;
  risk: Risk;
};

type TrafficLog = {
  time: string;
  protocol: string;
  source: string;
  action: Action;
  risk: Risk;
};

type ThreatAlert = {
  id: number;
  type: AlertType;
  sourceIp: string;
  protocol: string;
  risk: Risk;
  action: Action;
  timestamp: string;
  visible: boolean;
};

type Stats = {
  allowed: number;
  blocked: number;
  threats: number;
};

type NewRule = {
  protocol: string;
  sourceIp: string;
  action: Action;
};

const INITIAL_RULES: Rule[] = [
  { id: 1, protocol: 'ANY', sourceIp: 'ANY', action: 'ALLOW', description: 'Default Allow All' },
];

const SEVERITY_STYLES: Record<Risk, {
  label: string;
  card: string;
  text: string;
  border: string;
  glow: string;
  badge: string;
}> = {
  Critical: {
    label: 'CRITICAL',
    card: 'from-red-950/95 to-slate-950/95',
    text: 'text-red-200',
    border: 'border-red-500/70',
    glow: 'shadow-[0_0_36px_rgba(239,68,68,0.42)]',
    badge: 'bg-red-500 text-white',
  },
  High: {
    label: 'HIGH',
    card: 'from-orange-950/95 to-slate-950/95',
    text: 'text-orange-200',
    border: 'border-orange-500/70',
    glow: 'shadow-[0_0_32px_rgba(249,115,22,0.38)]',
    badge: 'bg-orange-500 text-white',
  },
  Medium: {
    label: 'MEDIUM',
    card: 'from-amber-950/95 to-slate-950/95',
    text: 'text-amber-200',
    border: 'border-amber-400/70',
    glow: 'shadow-[0_0_28px_rgba(245,158,11,0.34)]',
    badge: 'bg-amber-400 text-slate-950',
  },
  Low: {
    label: 'LOW',
    card: 'from-blue-950/95 to-slate-950/95',
    text: 'text-blue-200',
    border: 'border-blue-400/70',
    glow: 'shadow-[0_0_26px_rgba(96,165,250,0.3)]',
    badge: 'bg-blue-400 text-slate-950',
  },
};

const getThreatType = (packet: Packet): AlertType => {
  if (packet.protocol === 'MALWARE') return 'Malware Detected';
  if (packet.protocol === 'SSH') return 'SSH Brute Force';
  if (packet.protocol === 'HTTP') return packet.sourceIp.startsWith('192.168.') ? 'SQL Injection' : 'Suspicious Traffic';
  if (packet.protocol === 'HTTPS') return 'Unauthorized Access';
  if (packet.protocol === 'ICMP') return 'DDoS Attack';
  if (packet.protocol === 'FTP' || packet.protocol === 'RDP') return 'Port Scanning';
  return 'Suspicious Traffic';
};

const shouldTriggerAlert = (packet: Packet, action: Action) => (
  action === 'BLOCK' ||
  packet.risk === 'High' ||
  packet.risk === 'Critical' ||
  packet.sourceIp.startsWith('192.168.')
);

const App = () => {
  const [rules, setRules] = useState<Rule[]>(INITIAL_RULES);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [logs, setLogs] = useState<TrafficLog[]>([]);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [stats, setStats] = useState<Stats>({ allowed: 0, blocked: 0, threats: 0 });
  const [isRunning, setIsRunning] = useState(true);
  const [newRule, setNewRule] = useState<NewRule>({ protocol: 'HTTP', sourceIp: '', action: 'BLOCK' });
  const [firewallMode, setFirewallMode] = useState<FirewallMode>('BLACKLIST'); // BLACKLIST (Allow all except...) or WHITELIST (Block all except...)
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [firewallAlerting, setFirewallAlerting] = useState(false);

  const packetIdRef = useRef(0);
  const alertIdRef = useRef(0);
  const firewallPulseTimeoutRef = useRef<number | null>(null);

  const activeAlerts = alerts.filter(alert => alert.visible);
  const latestAlert = alerts[0];
  const severitySummary = useMemo(() => {
    return alerts.reduce<Record<Risk, number>>((summary, alert) => {
      summary[alert.risk] += 1;
      return summary;
    }, { Low: 0, Medium: 0, High: 0, Critical: 0 });
  }, [alerts]);

  const dismissAlert = (id: number) => {
    setAlerts(prev => prev.map(alert => (
      alert.id === id ? { ...alert, visible: false } : alert
    )));
  };

  const playAlertSound = () => {
    if (!soundEnabled) return;

    const AudioContextClass = window.AudioContext || (window as typeof window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!AudioContextClass) return;

    const audioContext = new AudioContextClass();
    const oscillator = audioContext.createOscillator();
    const gain = audioContext.createGain();

    oscillator.type = 'sine';
    oscillator.frequency.setValueAtTime(720, audioContext.currentTime);
    oscillator.frequency.exponentialRampToValueAtTime(360, audioContext.currentTime + 0.22);
    gain.gain.setValueAtTime(0.001, audioContext.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.12, audioContext.currentTime + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.001, audioContext.currentTime + 0.24);
    oscillator.connect(gain);
    gain.connect(audioContext.destination);
    oscillator.start();
    oscillator.stop(audioContext.currentTime + 0.26);
  };

  const triggerAlert = (packet: Packet, action: Action) => {
    const id = alertIdRef.current++;
    const alert: ThreatAlert = {
      id,
      type: getThreatType(packet),
      sourceIp: packet.sourceIp,
      protocol: packet.protocol,
      risk: packet.risk,
      action,
      timestamp: new Date().toLocaleTimeString(),
      visible: true,
    };

    setAlerts(prev => [alert, ...prev].slice(0, 25));
    setStats(s => ({ ...s, threats: s.threats + 1 }));
    setFirewallAlerting(true);
    playAlertSound();

    if (firewallPulseTimeoutRef.current) {
      window.clearTimeout(firewallPulseTimeoutRef.current);
    }

    firewallPulseTimeoutRef.current = window.setTimeout(() => {
      setFirewallAlerting(false);
    }, 2600);

    window.setTimeout(() => dismissAlert(id), 6500);
  };

  // Fungsi untuk mengevaluasi paket berdasarkan aturan
  const evaluatePacket = (packet: Packet): Action => {
    // Cari aturan yang cocok (dari atas ke bawah - First Match wins)
    // Di simulasi ini kita gunakan logika: Rule spesifik mengalahkan default
    
    let decision: Action = firewallMode === 'WHITELIST' ? 'BLOCK' : 'ALLOW';

    // Cari aturan yang spesifik untuk protokol atau IP ini
    const matchingRule = rules.find(r => 
      (r.protocol === 'ANY' || r.protocol === packet.protocol) &&
      (r.sourceIp === 'ANY' || r.sourceIp === packet.sourceIp)
    );

    if (matchingRule) {
      decision = matchingRule.action;
    }

    return decision;
  };

  // Generator Paket Otomatis
  useEffect(() => {
    if (!isRunning) return;

    const interval = setInterval(() => {
      const proto = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
      const isSuspect = Math.random() > 0.7;
      const sourceIp = isSuspect ? `192.168.1.${Math.floor(Math.random() * 255)}` : `10.0.0.${Math.floor(Math.random() * 255)}`;
      
      const newPacket: Packet = {
        id: packetIdRef.current++,
        protocol: proto.id,
        color: proto.color,
        sourceIp: sourceIp,
        x: 0, // Mulai dari Internet (Kiri)
        status: 'PENDING',
        risk: proto.risk
      };

      setPackets(prev => [...prev, newPacket]);
    }, 1500);

    return () => clearInterval(interval);
  }, [isRunning, rules, firewallMode]);

  // Animasi & Logika Pergerakan Paket
  useEffect(() => {
    if (!isRunning) return;

    const animationInterval = setInterval(() => {
      setPackets(prevPackets => {
        const nextPackets: Packet[] = [];
        
        prevPackets.forEach(p => {
          let nextX = p.x + 2;
          let nextStatus = p.status;

          // Titik Firewall (Tengah - sekitar x=45)
          if (p.x < 45 && nextX >= 45) {
            const decision = evaluatePacket(p);
            nextStatus = decision;
            
            // Update Stats & Logs
            if (decision === 'ALLOW') {
              setStats(s => ({ ...s, allowed: s.allowed + 1 }));
            } else {
              setStats(s => ({ 
                ...s, 
                blocked: s.blocked + 1
              }));
            }

            if (shouldTriggerAlert(p, decision)) {
              triggerAlert(p, decision);
            }

            setLogs(prevLogs => [{
              time: new Date().toLocaleTimeString(),
              protocol: p.protocol,
              source: p.sourceIp,
              action: decision,
              risk: p.risk
            }, ...prevLogs].slice(0, 10));
          }

          // Hapus paket jika sudah sampai tujuan atau diblokir
          if (nextX < 100 && nextStatus !== 'BLOCK') {
            nextPackets.push({ ...p, x: nextX, status: nextStatus });
          } else if (nextStatus === 'BLOCK' && p.x < 55) {
            // Animasi terpental sebentar sebelum hilang
            nextPackets.push({ ...p, x: nextX, status: nextStatus });
          }
        });

        return nextPackets;
      });
    }, 50);

    return () => clearInterval(animationInterval);
  }, [isRunning, rules, firewallMode]);

  const addRule = () => {
    if (newRule.sourceIp === '') {
      const updatedRule = { ...newRule, id: Date.now(), sourceIp: 'ANY' };
      setRules(prevRules => [updatedRule, ...prevRules]);
    } else {
      setRules(prevRules => [{ ...newRule, id: Date.now() }, ...prevRules]);
    }
  };

  const deleteRule = (id: number) => {
    setRules(prevRules => prevRules.filter(r => r.id !== id));
  };

  const resetSim = () => {
    setPackets([]);
    setLogs([]);
    setAlerts([]);
    setStats({ allowed: 0, blocked: 0, threats: 0 });
    setRules(INITIAL_RULES);
    setFirewallAlerting(false);
  };

  useEffect(() => {
    return () => {
      if (firewallPulseTimeoutRef.current) {
        window.clearTimeout(firewallPulseTimeoutRef.current);
      }
    };
  }, []);

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-8 font-sans">
      <div className="fixed right-6 top-6 z-50 flex w-[360px] flex-col gap-3">
        <AnimatePresence>
          {activeAlerts.slice(0, 3).map(alert => {
            const severity = SEVERITY_STYLES[alert.risk];

            return (
              <motion.div
                key={alert.id}
                initial={{ opacity: 0, x: 80, scale: 0.96 }}
                animate={{ opacity: 1, x: 0, scale: 1 }}
                exit={{ opacity: 0, x: 80, scale: 0.96 }}
                transition={{ type: 'spring', stiffness: 320, damping: 28 }}
                className={`overflow-hidden rounded-xl border bg-gradient-to-br ${severity.card} ${severity.border} ${severity.glow} backdrop-blur`}
              >
                <div className="border-b border-white/10 px-4 py-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="blink-warning text-red-400" size={18} />
                      <p className={`text-sm font-black uppercase tracking-widest ${severity.text}`}>[!] {alert.type}</p>
                    </div>
                    <span className={`rounded px-2 py-0.5 text-[10px] font-black ${severity.badge}`}>{severity.label}</span>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-2 px-4 py-3 text-xs">
                  <span className="text-slate-500">Source</span>
                  <span className="font-mono text-slate-100">{alert.sourceIp}</span>
                  <span className="text-slate-500">Protocol</span>
                  <span className="font-bold text-cyan-300">{alert.protocol}</span>
                  <span className="text-slate-500">Action</span>
                  <span className={alert.action === 'BLOCK' ? 'font-black text-red-300' : 'font-black text-green-300'}>
                    {alert.action === 'BLOCK' ? 'BLOCKED' : 'ALLOWED'}
                  </span>
                  <span className="text-slate-500">Timestamp</span>
                  <span className="font-mono text-slate-300">{alert.timestamp}</span>
                </div>
                <div className="flex items-center justify-end gap-2 border-t border-white/10 px-4 py-3">
                  <button
                    className="rounded-md border border-cyan-400/40 px-3 py-1.5 text-xs font-bold text-cyan-200 transition hover:bg-cyan-400/10"
                    onClick={() => document.getElementById('alert-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
                  >
                    View Details
                  </button>
                  <button
                    className="rounded-md border border-slate-600 px-3 py-1.5 text-xs font-bold text-slate-300 transition hover:bg-slate-700"
                    onClick={() => dismissAlert(alert.id)}
                  >
                    Dismiss
                  </button>
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>

      {/* Header */}
      <header className="max-w-6xl mx-auto mb-8 flex flex-row justify-between items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Shield className="text-cyan-400 w-8 h-8" />
            Firewall Lab Simulator
          </h1>
          <p className="text-slate-400">Visualisasi Keamanan Infrastruktur Jaringan</p>
        </div>
        <div className="flex gap-3">
          <button 
            onClick={() => setIsRunning(!isRunning)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-semibold transition ${isRunning ? 'bg-amber-500 hover:bg-amber-600' : 'bg-green-500 hover:bg-green-600'}`}
          >
            {isRunning ? <Pause size={18} /> : <Play size={18} />}
            {isRunning ? 'Pause' : 'Resume'}
          </button>
          <button 
            onClick={resetSim}
            className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg font-semibold transition"
          >
            <RefreshCw size={18} /> Reset
          </button>
        </div>
      </header>

      <main className="max-w-6xl mx-auto grid grid-cols-3 gap-8">
        
        {/* Kolom Kiri: Dashboard Visualisasi */}
        <div className="col-span-2 space-y-6">
          
          {/* Monitor Visualisasi */}
          <div className="bg-slate-800 rounded-2xl p-6 border border-slate-700 shadow-xl relative overflow-hidden h-80">
            <div className="absolute inset-0 opacity-10 pointer-events-none" style={{ backgroundImage: 'radial-gradient(#2dd4bf 0.5px, transparent 0.5px)', backgroundSize: '24px 24px' }}></div>
            
            <div className="flex justify-between items-center mb-12 relative z-10">
              <div className="flex flex-col items-center gap-2">
                <div className="p-4 bg-slate-700 rounded-full border border-slate-600">
                  <Globe className="text-blue-400" size={32} />
                </div>
                <span className="text-xs font-bold uppercase tracking-widest text-slate-500">Untrusted (Internet)</span>
              </div>

              <div className="flex flex-col items-center gap-2">
                <div className={`p-6 rounded-2xl border-2 transition-all duration-500 ${firewallAlerting ? 'firewall-threat-pulse bg-red-900/50 border-red-500 shadow-[0_0_36px_rgba(239,68,68,0.55)]' : stats.threats > 5 ? 'bg-orange-900/30 border-orange-500 shadow-[0_0_24px_rgba(249,115,22,0.28)]' : 'bg-slate-700 border-cyan-500'}`}>
                  {firewallAlerting || stats.threats > 5 ? <ShieldAlert className="text-red-500 animate-pulse" size={48} /> : <ShieldCheck className="text-cyan-400" size={48} />}
                </div>
                <span className="text-xs font-bold uppercase tracking-widest text-cyan-500">Firewall Node</span>
              </div>

              <div className="flex flex-col items-center gap-2">
                <div className="p-4 bg-slate-700 rounded-full border border-slate-600 text-green-400">
                  <Server size={32} />
                </div>
                <span className="text-xs font-bold uppercase tracking-widest text-slate-500">Trusted (Internal)</span>
              </div>
            </div>

            {/* Jalur Paket */}
            <div className="relative w-full h-1 bg-slate-700 top-1/2 -translate-y-8">
              {packets.map(packet => (
                <div 
                  key={packet.id}
                  className={`absolute top-0 -translate-y-1/2 w-4 h-4 rounded-full shadow-lg flex items-center justify-center transition-opacity duration-300 ${packet.color} ${packet.status === 'BLOCK' ? 'opacity-50 ring-4 ring-red-500/50' : 'opacity-100 ring-2 ring-white/20'}`}
                  style={{ 
                    left: `${packet.x}%`,
                    transition: 'left 0.05s linear'
                  }}
                >
                  <div className="absolute -top-6 text-[10px] font-bold whitespace-nowrap bg-slate-900/80 px-1 rounded">
                    {packet.protocol}
                  </div>
                  {packet.status === 'BLOCK' && <div className="text-white text-[10px] font-bold">X</div>}
                </div>
              ))}
            </div>
          </div>

          {/* Statistik & Info */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-slate-800 p-4 rounded-xl border border-slate-700 flex items-center gap-4">
              <div className="p-3 bg-green-500/10 rounded-lg text-green-500"><ShieldCheck /></div>
              <div>
                <p className="text-sm text-slate-400">Allowed</p>
                <p className="text-2xl font-bold">{stats.allowed}</p>
              </div>
            </div>
            <div className="bg-slate-800 p-4 rounded-xl border border-slate-700 flex items-center gap-4">
              <div className="p-3 bg-red-500/10 rounded-lg text-red-500"><ShieldAlert /></div>
              <div>
                <p className="text-sm text-slate-400">Blocked</p>
                <p className="text-2xl font-bold">{stats.blocked}</p>
              </div>
            </div>
            <div className="bg-slate-800 p-4 rounded-xl border border-slate-700 flex items-center gap-4">
              <div className="p-3 bg-amber-500/10 rounded-lg text-amber-500"><AlertTriangle /></div>
              <div>
                <p className="text-sm text-slate-400">Threats</p>
                <p className="text-2xl font-bold">{stats.threats}</p>
              </div>
            </div>
          </div>

          {/* Log Riwayat */}
          <div className="bg-slate-800 rounded-2xl border border-slate-700 overflow-hidden">
            <div className="bg-slate-700/50 px-6 py-4 border-b border-slate-700 flex items-center justify-between">
              <h3 className="font-bold flex items-center gap-2"><History size={18} /> Traffic Logs</h3>
              <span className="text-xs bg-slate-600 px-2 py-1 rounded">Real-time Analysis</span>
            </div>
            <div className="p-0 max-h-60 overflow-y-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-800/50 sticky top-0">
                  <tr>
                    <th className="px-6 py-3 text-slate-400 font-medium">Time</th>
                    <th className="px-6 py-3 text-slate-400 font-medium">Source IP</th>
                    <th className="px-6 py-3 text-slate-400 font-medium">Protocol</th>
                    <th className="px-6 py-3 text-slate-400 font-medium">Risk</th>
                    <th className="px-6 py-3 text-slate-400 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700">
                  {logs.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-6 py-8 text-center text-slate-500 italic">Belum ada trafik yang tercatat...</td>
                    </tr>
                  ) : (
                    logs.map((log, i) => (
                      <tr key={i} className="hover:bg-slate-700/30 transition">
                        <td className="px-6 py-3 text-slate-400">{log.time}</td>
                        <td className="px-6 py-3 font-mono">{log.source}</td>
                        <td className="px-6 py-3 font-bold text-cyan-400">{log.protocol}</td>
                        <td className="px-6 py-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            log.risk === 'Critical' ? 'bg-red-500 text-white' :
                            log.risk === 'High' ? 'bg-orange-500 text-white' :
                            log.risk === 'Medium' ? 'bg-amber-500 text-white' : 'bg-slate-600 text-slate-300'
                          }`}>
                            {log.risk}
                          </span>
                        </td>
                        <td className="px-6 py-3">
                          <span className={`flex items-center gap-1 font-bold ${log.action === 'ALLOW' ? 'text-green-500' : 'text-red-500'}`}>
                            {log.action === 'ALLOW' ? <Unlock size={14} /> : <Lock size={14} />}
                            {log.action}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Kolom Kanan: Firewall Policy Manager */}
        <div className="space-y-6">
          <div id="alert-panel" className="overflow-hidden rounded-2xl border border-red-500/30 bg-slate-950/80 shadow-[0_0_38px_rgba(239,68,68,0.16)]">
            <div className="border-b border-red-500/20 bg-gradient-to-r from-red-950/70 via-slate-900 to-orange-950/40 px-6 py-4">
              <div className="flex items-center justify-between">
                <h3 className="flex items-center gap-2 font-bold">
                  <AlertTriangle className="blink-warning text-red-400" size={18} />
                  Alert Notification System
                </h3>
                <button
                  onClick={() => setSoundEnabled(enabled => !enabled)}
                  className={`rounded-md border px-3 py-1.5 text-[11px] font-black uppercase tracking-wider transition ${
                    soundEnabled
                      ? 'border-cyan-400/50 bg-cyan-400/10 text-cyan-200'
                      : 'border-slate-700 text-slate-500 hover:text-slate-300'
                  }`}
                >
                  Sound {soundEnabled ? 'On' : 'Off'}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 p-4">
              <div className="rounded-xl border border-slate-700 bg-slate-900/80 p-3">
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Active Alerts</p>
                <p className="mt-1 text-2xl font-black text-red-300">{activeAlerts.length}</p>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-900/80 p-3">
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Total Threats</p>
                <p className="mt-1 text-2xl font-black text-orange-300">{stats.threats}</p>
              </div>
              <div className="col-span-2 rounded-xl border border-slate-700 bg-slate-900/80 p-3">
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Last Detection</p>
                {latestAlert ? (
                  <div className="mt-2 flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-black text-slate-100">{latestAlert.type}</p>
                      <p className="font-mono text-xs text-slate-500">{latestAlert.sourceIp} / {latestAlert.protocol}</p>
                    </div>
                    <span className={`shrink-0 rounded px-2 py-1 text-[10px] font-black ${SEVERITY_STYLES[latestAlert.risk].badge}`}>
                      {SEVERITY_STYLES[latestAlert.risk].label}
                    </span>
                  </div>
                ) : (
                  <p className="mt-2 text-sm text-slate-500">No detection yet</p>
                )}
              </div>
            </div>

            <div className="px-4 pb-4">
              <p className="mb-3 text-[10px] font-bold uppercase tracking-widest text-slate-500">Threat Severity Summary</p>
              <div className="grid grid-cols-4 gap-2">
                {(['Critical', 'High', 'Medium', 'Low'] as Risk[]).map(risk => (
                  <div key={risk} className={`rounded-lg border ${SEVERITY_STYLES[risk].border} bg-slate-900/70 p-2 text-center`}>
                    <p className={`text-lg font-black ${SEVERITY_STYLES[risk].text}`}>{severitySummary[risk]}</p>
                    <p className="text-[9px] font-bold uppercase text-slate-500">{risk}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="border-t border-slate-800 px-4 py-4">
              <p className="mb-3 text-[10px] font-bold uppercase tracking-widest text-slate-500">Alert History</p>
              <div className="max-h-44 space-y-2 overflow-y-auto pr-2 custom-scrollbar">
                {alerts.length === 0 ? (
                  <div className="rounded-lg border border-dashed border-slate-700 p-4 text-center text-xs text-slate-500">
                    Menunggu ancaman realtime...
                  </div>
                ) : (
                  alerts.slice(0, 8).map(alert => (
                    <div key={alert.id} className="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="truncate text-xs font-black text-slate-200">{alert.type}</p>
                        <span className={`rounded px-1.5 py-0.5 text-[9px] font-black ${SEVERITY_STYLES[alert.risk].badge}`}>
                          {SEVERITY_STYLES[alert.risk].label}
                        </span>
                      </div>
                      <div className="mt-1 flex justify-between gap-2 text-[11px] text-slate-500">
                        <span className="font-mono">{alert.sourceIp}</span>
                        <span>{alert.timestamp}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
          
          {/* Konfigurasi Aturan */}
          <div className="bg-slate-800 rounded-2xl border border-slate-700 overflow-hidden flex flex-col h-full shadow-xl">
            <div className="bg-slate-700/50 px-6 py-4 border-b border-slate-700">
              <h3 className="font-bold flex items-center gap-2"><Activity size={18} /> Policy Manager</h3>
            </div>
            
            <div className="p-6 space-y-6">
              {/* Toggle Mode */}
              <div className="p-1 bg-slate-900 rounded-xl flex">
                <button 
                  onClick={() => setFirewallMode('BLACKLIST')}
                  className={`flex-1 py-2 px-4 rounded-lg text-sm font-bold transition ${firewallMode === 'BLACKLIST' ? 'bg-slate-700 text-white shadow-lg' : 'text-slate-500'}`}
                >
                  Blacklist
                </button>
                <button 
                  onClick={() => setFirewallMode('WHITELIST')}
                  className={`flex-1 py-2 px-4 rounded-lg text-sm font-bold transition ${firewallMode === 'WHITELIST' ? 'bg-slate-700 text-white shadow-lg' : 'text-slate-500'}`}
                >
                  Whitelist
                </button>
              </div>

              {/* Form Tambah Aturan */}
              <div className="bg-slate-900/50 p-4 rounded-xl space-y-4 border border-slate-700/50">
                <p className="text-xs font-bold text-slate-500 uppercase tracking-widest">Tambah Aturan Baru</p>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-[10px] text-slate-500 uppercase font-bold">Protokol</label>
                    <select 
                      className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-sm focus:ring-2 ring-cyan-500 outline-none"
                      value={newRule.protocol}
                      onChange={(e) => setNewRule({...newRule, protocol: e.target.value})}
                    >
                      <option value="ANY">ANY</option>
                      {PROTOCOLS.map(p => <option key={p.id} value={p.id}>{p.id}</option>)}
                    </select>
                  </div>
                  <div className="space-y-1">
                    <label className="text-[10px] text-slate-500 uppercase font-bold">Tindakan</label>
                    <select 
                      className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-sm focus:ring-2 ring-cyan-500 outline-none"
                      value={newRule.action}
                      onChange={(e) => setNewRule({...newRule, action: e.target.value as Action})}
                    >
                      <option value="ALLOW">ALLOW</option>
                      <option value="BLOCK">BLOCK</option>
                    </select>
                  </div>
                </div>
                <div className="space-y-1">
                  <label className="text-[10px] text-slate-500 uppercase font-bold">Source IP (Kosongkan utk ANY)</label>
                  <input 
                    type="text" 
                    placeholder="192.168.1.1 atau ANY"
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-sm focus:ring-2 ring-cyan-500 outline-none font-mono"
                    value={newRule.sourceIp}
                    onChange={(e) => setNewRule({...newRule, sourceIp: e.target.value})}
                  />
                </div>
                <button 
                  onClick={addRule}
                  className="w-full bg-cyan-500 hover:bg-cyan-600 text-slate-900 font-bold py-2 rounded-lg flex items-center justify-center gap-2 transition active:scale-95"
                >
                  <Plus size={18} /> Tambah Rule
                </button>
              </div>

              {/* List Rules Terpasang */}
              <div className="space-y-3">
                <p className="text-xs font-bold text-slate-500 uppercase tracking-widest flex justify-between">
                  Active Rules <span>{rules.length}</span>
                </p>
                <div className="space-y-2 max-h-64 overflow-y-auto pr-2 custom-scrollbar">
                  {rules.map(rule => (
                    <div key={rule.id} className="bg-slate-700/30 border border-slate-700 p-3 rounded-xl flex justify-between items-center hover:border-slate-500 transition">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${rule.action === 'ALLOW' ? 'text-green-400 bg-green-400/10' : 'text-red-400 bg-red-400/10'}`}>
                          {rule.action === 'ALLOW' ? <Unlock size={16} /> : <Lock size={16} />}
                        </div>
                        <div>
                          <p className="text-sm font-bold">{rule.protocol} <span className="text-slate-500 font-normal text-xs ml-1">({rule.sourceIp})</span></p>
                          <p className={`text-[10px] font-bold uppercase ${rule.action === 'ALLOW' ? 'text-green-500' : 'text-red-500'}`}>
                            {rule.action}
                          </p>
                        </div>
                      </div>
                      {rule.id !== 1 && (
                        <button onClick={() => deleteRule(rule.id)} className="text-slate-500 hover:text-red-400 p-1 transition">
                          <Trash2 size={16} />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

            </div>

            {/* Narasi Edukasi */}
            <div className="mt-auto p-6 bg-slate-900/50 border-t border-slate-700">
               <div className="flex gap-3 text-xs text-slate-400 italic">
                  <AlertTriangle className="text-amber-500 shrink-0" size={16} />
                  <p>
                    <strong>Lab Guide:</strong> Cobalah set mode ke <strong>Whitelist</strong>. Semua trafik akan terblokir sampai kamu menambahkan aturan "ALLOW" yang spesifik. Amati log untuk melihat serangan MALWARE yang masuk!
                  </p>
               </div>
            </div>
          </div>
          
        </div>
      </main>
      
      <style>{`
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #475569; border-radius: 10px; }
        .blink-warning {
          animation: blink-warning 0.9s ease-in-out infinite;
          filter: drop-shadow(0 0 10px rgba(248, 113, 113, 0.85));
        }
        .firewall-threat-pulse {
          animation: firewall-threat-pulse 1.05s ease-in-out infinite;
        }
        @keyframes blink-warning {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.38; transform: scale(1.12); }
        }
        @keyframes firewall-threat-pulse {
          0%, 100% {
            box-shadow: 0 0 24px rgba(239, 68, 68, 0.45), inset 0 0 16px rgba(239, 68, 68, 0.16);
          }
          50% {
            box-shadow: 0 0 54px rgba(249, 115, 22, 0.7), inset 0 0 28px rgba(248, 113, 113, 0.24);
          }
        }
      `}</style>
    </div>
  );
};

export default App;
