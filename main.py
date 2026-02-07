# ids_app_final.py
# FINAL PRODUCTION VERSION
# -----------------------------------------------------------------------------
# Secure Network Intrusion Detection System (NIDS)
# Features: Adaptive Learning, Signature + Anomaly Engines, Automated Blocking
# -----------------------------------------------------------------------------

import streamlit as st
import numpy as np
import time, json, logging, threading, os, sys, ipaddress, subprocess, re, shutil
from collections import defaultdict, deque
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, Raw, PcapReader, wrpcap

# ==============================
# 1. CONFIGURATION
# ==============================
CONFIG = {
    "system": {
        "interface": os.getenv("IDS_IFACE", "en0" if sys.platform == "darwin" else "eth0"),
        "block_mode": "alert", 
    },
    "thresholds": {
        "exfil_bps": 1_000_000,
        "exfil_size": 10_000_000,
        "scan_ports": 20,
        "icmp_rate": 100,
        "payload_limit": 1500,
        "anomaly_score": 50.0,
        "min_bandwidth": 100_000,
    },
    "whitelist": ["8.8.8.8", "8.8.4.4", "1.1.1.1", "127.0.0.1", "0.0.0.0"],
    "internal_nets": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8"],
    "safe_ports": {80, 443, 8080, 8443, 53, 5353, 123} 
}

DATA_DIR = "data"
if not os.path.exists(DATA_DIR): os.makedirs(DATA_DIR)
logging.basicConfig(filename="ids_events.log", level=logging.WARNING, format='%(asctime)s %(message)s')

# ==============================
# 2. CORE CLASSES
# ==============================
class BlockManager:
    def __init__(self, mode):
        self.mode = mode
        self.iptables_path = shutil.which("iptables")

    def is_blockable(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback or ip.is_link_local or ip.is_multicast: return False
            if ip_str in CONFIG["whitelist"]: return False
            return True
        except ValueError: return False

    def block_ip(self, ip):
        if self.mode != "auto" or not self.iptables_path: return False
        if not self.is_blockable(ip): return False
        try:
            subprocess.run(["sudo", self.iptables_path, "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True, timeout=2)
            return True
        except: return False

class DeepPacketInspection:
    def __init__(self):
        self.signatures = [
            (re.compile(b"UNION[\s\+%]+SELECT", re.IGNORECASE), "SQL Injection", "HIGH"),
            (re.compile(b"<script[^>]*>.*?</script>", re.IGNORECASE), "XSS Attempt", "MEDIUM"),
            (re.compile(b"alert\(", re.IGNORECASE), "XSS Attempt", "MEDIUM"),
            (re.compile(b"\xff\x53\x4d\x42", re.IGNORECASE), "SMBv1 Exploit", "CRITICAL"),
            (re.compile(b"cmd\.exe|powershell|/bin/bash|/bin/sh", re.IGNORECASE), "RCE Attempt", "CRITICAL"),
            (re.compile(b"sqlmap|nikto|hydra|nmap", re.IGNORECASE), "Scanner Tool", "MEDIUM"),
        ]
        self.max_len = CONFIG["thresholds"]["payload_limit"]
    
    def inspect(self, payload):
        if not payload: return None
        chunk = payload[:self.max_len]
        for pattern, name, sev in self.signatures:
            if pattern.search(chunk): return {"name": name, "severity": sev}
        return None

class SignatureIDS:
    def __init__(self): self.dpi = DeepPacketInspection()
    
    def detect_fast(self, f, pkt):
        if pkt and Raw in pkt:
            res = self.dpi.inspect(pkt[Raw].load)
            if res: return res
        if pkt and ICMP in pkt:
            if f["icmp"] > CONFIG["thresholds"]["icmp_rate"]:
                return {"name": "ICMP Flood (Ping of Death)", "severity": "MEDIUM"}
        return None

    def detect_periodic(self, f, scan_stats=None):
        if f["bytes_per_sec"] > CONFIG["thresholds"]["exfil_bps"]:
            return {"name": f"Exfil Burst ({f['bytes_per_sec']/1e6:.1f} MB/s)", "severity": "HIGH"}
        if scan_stats and len(scan_stats) > CONFIG["thresholds"]["scan_ports"]:
            return {"name": f"Port Scan ({len(scan_stats)} ports)", "severity": "MEDIUM"}
        if f["src_bytes"] > CONFIG["thresholds"]["exfil_size"]:
            if f["violation_start"] == 0: f["violation_start"] = time.time()
            elif (time.time() - f["violation_start"] > 5) and not f.get("alerted_exfil", False):
                f["alerted_exfil"] = True
                return {"name": "Data Exfil (Size > 10MB)", "severity": "HIGH"}
        return None

class RobustAnomalyIDS:
    def __init__(self):
        self.median = None; self.iqr = None; self.th = None; self.norm = None
        self.training_size = 0
    
    def fit(self, data):
        if len(data) < 50: return False
        X = np.array(data, float)
        self.training_size = len(X)
        X = np.log1p(X)
        self.median = np.median(X, axis=0)
        q75, q25 = np.percentile(X, [75, 25], axis=0)
        self.iqr = q75 - q25
        self.iqr[self.iqr == 0] = 1 
        self.norm = (X - self.median) / self.iqr
        
        subset_size = min(500, len(self.norm))
        subset = self.norm[np.random.choice(len(self.norm), subset_size, replace=False)]
        distances = [np.mean(np.sort(np.sqrt(((subset - p)**2).sum(1)))[:3]) for p in subset]
        self.th = np.percentile(distances, 99.5) * 2.0 
        return True
    
    def detect(self, feats):
        if self.norm is None: return False, 0.0
        f_log = np.log1p(np.array(feats, float))
        nf = (f_log - self.median) / self.iqr
        score = np.mean(np.sort(np.sqrt(((self.norm - nf)**2).sum(1)))[:3])
        return score > self.th, score

# ==============================
# 3. STATE & UTILS
# ==============================
class SharedState:
    def __init__(self):
        self.flows = {}
        self.alerts = deque(maxlen=200)
        self.blocked = {}
        self.sources = defaultdict(set)
        self.sniffer = None
        self.sig = SignatureIDS()
        self.anom = RobustAnomalyIDS()
        self.alert_history = {} 
        self.block_mgr = BlockManager(CONFIG["system"]["block_mode"])
        self.trained = False
        self.lock = threading.Lock()
        self.pkt_count = 0
        self.alert_seq = 0
        self.internal_nets = [ipaddress.ip_network(n, strict=False) for n in CONFIG["internal_nets"]]
        self.monitoring = False
        self.monitor_pkts = []
        self.monitor_sniffer = None
        self.tp = 0; self.fp = 0
        
        # Adaptive Components
        self.trusted_ips = set()
        self.ip_profiles = defaultdict(lambda: {
            "first_seen": 0, "anomaly_count": 0, "last_alert": 0,
            "avg_bandwidth": 0, "is_streaming": False, "verdict": None
        })
        self.load_trusted_ips()
        self.enable_anomaly_detection = False
        self.enable_signature_detection = True

    def save_trusted_ips(self):
        try:
            with open(os.path.join(DATA_DIR, "trusted_ips.json"), "w") as f:
                json.dump(list(self.trusted_ips), f)
        except: pass
    
    def load_trusted_ips(self):
        try:
            path = os.path.join(DATA_DIR, "trusted_ips.json")
            if os.path.exists(path):
                with open(path, "r") as f: self.trusted_ips = set(json.load(f))
        except: pass
    
    def get_precision(self):
        total = self.tp + self.fp
        return (self.tp / total) if total > 0 else 0.0

@st.cache_resource
def get_state(): return SharedState()
S = get_state()

def canonical_flow(src, dst, sport, dport, proto):
    a, b = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    return (src, dst, sport, dport, proto) if a < b else (dst, src, dport, sport, proto)

def is_internal(ip):
    try: return any(ipaddress.ip_address(ip) in net for net in S.internal_nets)
    except: return False

def log_alert(msg, ip, sev, kind, metadata=None):
    if ip in S.trusted_ips: return None
    
    prof = S.ip_profiles[ip]
    now = time.time()
    if prof["first_seen"] == 0: prof["first_seen"] = now
    
    if metadata and "bw" in metadata:
        bw = metadata["bw"]
        if prof["avg_bandwidth"] == 0: prof["avg_bandwidth"] = bw
        else: prof["avg_bandwidth"] = 0.7 * prof["avg_bandwidth"] + 0.3 * bw
        if prof["avg_bandwidth"] > 500_000: prof["is_streaming"] = True
    
    if kind == "ANOM":
        if prof["anomaly_count"] > 0 and prof["verdict"] != "TP": return None
        prof["anomaly_count"] += 1
    
    key = (ip, kind)
    if now - S.alert_history.get(key, 0) < 10: return None
    S.alert_history[key] = now
    
    S.alert_seq += 1
    alert = {"id": S.alert_seq, "timestamp": time.strftime("%H:%M:%S"), "src_ip": ip, "message": msg, "severity": sev, "category": kind, "label": None, "meta": metadata or {}}
    S.alerts.appendleft(alert)
    return S.alert_seq

# ==============================
# 4. PACKET HANDLERS
# ==============================
def monitor_handler(pkt):
    S.monitor_pkts.append(pkt)

def detect_handler(pkt):
    if IP not in pkt: return
    src, dst = pkt[IP].src, pkt[IP].dst
    if src in CONFIG["whitelist"] or dst in CONFIG["whitelist"]: return
    try:
        if ipaddress.ip_address(dst).is_multicast: return
    except: pass

    proto = pkt[IP].proto
    sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
    dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
    fid = canonical_flow(src, dst, sport, dport, proto)
    now = time.time()

    with S.lock:
        S.pkt_count += 1
        if S.pkt_count % 1000 == 0:
            S.flows = {k: v for k, v in S.flows.items() if now - v["last_seen"] < 120}
            S.sources.clear()

        if TCP in pkt and pkt[TCP].flags & 0x02: S.sources[src].add(dport)

        if fid not in S.flows:
            internal = [ip for ip in (src, dst) if is_internal(ip)]
            owner = internal[0] if len(internal) == 1 else None
            if owner is None: return
            S.flows[fid] = {
                "start": now, "last_seen": now, "pkts": 0, "src_bytes": 0, "dst_bytes": 0, "syns": 0, "icmp": 0,
                "owner": owner, "violation_start": 0, "alerted_exfil": False, "bytes_per_sec": 0, "rate_samples": deque(maxlen=5),
                "win_last_check": now, "win_last_src": 0, "win_last_dst": 0, "win_last_pkts": 0, "win_last_syns": 0
            }

        f = S.flows[fid]
        f["last_seen"] = now; f["pkts"] += 1
        if src == f["owner"]: f["src_bytes"] += len(pkt)
        else: f["dst_bytes"] += len(pkt)
        if TCP in pkt and pkt[TCP].flags & 0x02 and src == f["owner"]: f["syns"] += 1
        if ICMP in pkt: f["icmp"] += 1

        if f["pkts"] % 10 == 0:
            dt = max(now - f["start"], 1)
            vol = f["src_bytes"] if is_internal(f["owner"]) else f["dst_bytes"]
            f["rate_samples"].append(vol / dt)
            f["bytes_per_sec"] = np.mean(f["rate_samples"])

        if S.enable_signature_detection:
            r_fast = S.sig.detect_fast(f, pkt)
            if r_fast:
                target_ip = dst if src == f["owner"] else src
                aid = log_alert(r_fast["name"], target_ip, r_fast["severity"], "SIG")
                if aid: S.block_mgr.block_ip(target_ip)
                return

        if f["pkts"] % 20 == 0:
            if S.enable_signature_detection:
                r_per = S.sig.detect_periodic(f, S.sources.get(src))
                if r_per:
                    target_ip = dst if src == f["owner"] else src
                    aid = log_alert(r_per["name"], target_ip, r_per["severity"], "SIG")
                    if "Port Scan" in r_per["name"] and src in S.sources: S.sources[src].clear()
                    if aid: S.block_mgr.block_ip(target_ip)
                    return

            if S.enable_anomaly_detection and S.trained:
                dt_win = now - f["win_last_check"]
                if dt_win > 5.0:
                    src_rate = (f["src_bytes"] - f["win_last_src"]) / dt_win
                    dst_rate = (f["dst_bytes"] - f["win_last_dst"]) / dt_win
                    pkt_rate = (f["pkts"] - f["win_last_pkts"]) / dt_win
                    syn_rate = (f["syns"] - f["win_last_syns"]) / dt_win

                    target = dst if src == f["owner"] else src
                    bandwidth = max(src_rate, dst_rate)
                    
                    skip_detection = (
                        target in S.trusted_ips or
                        sport in CONFIG["safe_ports"] or dport in CONFIG["safe_ports"] or
                        bandwidth > CONFIG["thresholds"]["min_bandwidth"] or
                        S.ip_profiles[target].get("is_streaming", False)
                    )
                    
                    if not skip_detection:
                        feats = [src_rate, dst_rate, pkt_rate, syn_rate]
                        anom, score = S.anom.detect(feats)
                        if anom and score > CONFIG["thresholds"]["anomaly_score"]:
                            log_alert(f"Anomaly ({score:.1f})", target, "MEDIUM", "ANOM", metadata={"bw": bandwidth, "score": score})
                    
                    f["win_last_check"] = now
                    f["win_last_src"] = f["src_bytes"]
                    f["win_last_dst"] = f["dst_bytes"]
                    f["win_last_pkts"] = f["pkts"]
                    f["win_last_syns"] = f["syns"]

# ==============================
# 5. UI
# ==============================
st.set_page_config(page_title="Secure NIDS", layout="wide")
st.title("🛡️ Secure NIDS + IPS (Production Edition)")

with st.sidebar:
    st.header("⚙️ Configuration")
    iface = st.text_input("Network Interface", CONFIG["system"]["interface"])
    mode = st.radio("Operating Mode", ["Monitor", "Train", "Active Detect", "Demo"])
    st.divider()
    
    st.subheader("🎛️ Detection Engines")
    S.enable_signature_detection = st.checkbox("Signature Detection", value=S.enable_signature_detection, help="Fast pattern matching for known attacks")
    anom_enabled = st.checkbox("Anomaly Detection (ML)", value=S.enable_anomaly_detection, help="Statistical analysis for unusual traffic patterns")
    
    if anom_enabled and not S.trained:
        st.warning("⚠️ Model not trained! Train first.")
        S.enable_anomaly_detection = False
    else:
        S.enable_anomaly_detection = anom_enabled
    
    st.divider()
    st.subheader("🧠 Adaptive Intelligence")
    st.metric("Trusted IPs", len(S.trusted_ips))
    
    if st.button("🗑️ Reset Learning"):
        S.trusted_ips.clear(); S.ip_profiles.clear(); S.save_trusted_ips()
        st.success("Memory wiped!"); st.rerun()
    
    # Show trusted IPs
    if S.trusted_ips and st.checkbox("Show Trusted IPs"):
        for ip in list(S.trusted_ips)[:10]:
            st.text(f"✅ {ip}")
    
    st.divider()
    st.subheader("📊 System Health")
    if S.trained: st.success(f"✅ Model: TRAINED ({S.anom.training_size} flows)")
    else: st.error("❌ Model: UNTRAINED")
    
    if S.sniffer and S.sniffer.running: st.success("✅ Sensor: ACTIVE")
    elif S.monitoring: st.info("⏺️ Monitor: RECORDING")
    else: st.warning("⚠️ Sensor: STOPPED")

def stop_all():
    if S.sniffer and S.sniffer.running: S.sniffer.stop()
    if S.monitor_sniffer and S.monitor_sniffer.running: S.monitor_sniffer.stop()
    S.monitoring = False

if mode == "Monitor":
    st.header("📡 1. Baseline Traffic Capture")
    st.info("💡 **Tip:** Capture 3-5 minutes of normal browsing (YouTube, Reddit, Email) for best training results.")
    c1, c2 = st.columns(2)
    with c1:
        if not S.monitoring:
            if st.button("▶️ START RECORDING", type="primary"):
                stop_all(); S.monitor_pkts = []; S.monitoring = True
                S.monitor_sniffer = AsyncSniffer(prn=monitor_handler, store=0, iface=iface)
                S.monitor_sniffer.start(); st.rerun()
        else:
            st.write(f"### 🔴 Recording... {len(S.monitor_pkts)} packets")
            if st.button("🔄 Refresh Status"): st.rerun()
    with c2:
        if S.monitoring and st.button("⏹️ STOP & SAVE"):
            S.monitor_sniffer.stop(); S.monitoring = False
            fname = os.path.join(DATA_DIR, f"capture_{int(time.time())}.pcap")
            wrpcap(fname, S.monitor_pkts)
            st.success(f"✅ Saved {len(S.monitor_pkts)} packets to `{fname}`"); st.rerun()

elif mode == "Train":
    stop_all()
    st.header("🎓 2. Model Training")
    files = [f for f in os.listdir(DATA_DIR) if f.endswith(".pcap")]
    if not files: 
        st.error("❌ No PCAP files found! Capture traffic in Monitor mode first.")
        st.stop()
    
    sel = st.selectbox("Select Training PCAP", files)
    st.info("📋 **Training will analyze ALL packets in the file. This may take 1-2 minutes for large captures.**")
    
    if st.button("🚀 Train Model", type="primary"):
        flows = defaultdict(lambda: {"start": 0, "pkts": 0, "src": 0, "dst": 0, "syns": 0})
        training_data = []
        status_text = st.empty()
        progress_bar = st.progress(0)
        
        status_text.text("📖 Reading PCAP file...")
        pkt_count = 0
        
        with PcapReader(os.path.join(DATA_DIR, sel)) as reader:
            for pkt in reader:
                pkt_count += 1
                if pkt_count % 1000 == 0: 
                    status_text.text(f"Processing packet {pkt_count}...")
                
                if IP in pkt:
                    fid = canonical_flow(pkt[IP].src, pkt[IP].dst, 0, 0, pkt[IP].proto)
                    f = flows[fid]
                    if f["pkts"] == 0: f["start"] = pkt.time
                    f["pkts"] += 1
                    if is_internal(pkt[IP].src): f["src"] += len(pkt)
                    else: f["dst"] += len(pkt)
                    if TCP in pkt and pkt[TCP].flags & 0x02: f["syns"] += 1
        
        status_text.text("🧮 Calculating features...")
        for f in flows.values():
            dur = max(0.1, time.time() - f["start"])
            training_data.append([f["src"] / dur, f["dst"] / dur, f["pkts"] / dur, f["syns"] / dur])
        
        # CRITICAL: Show diagnostics and validate
        st.write("### 📊 Training Data Quality")
        st.write(f"- **Total Packets:** {pkt_count:,}")
        st.write(f"- **Unique Flows:** {len(flows)}")
        
        if len(flows) < 50:
            progress_bar.empty()
            status_text.empty()
            st.error(f"⚠️ **INSUFFICIENT DATA!** Only {len(flows)} flows detected. Need at least 50.")
            st.info("💡 **Solution:** Capture 3-5 minutes of diverse traffic (browse multiple websites, stream video, etc.)")
            st.stop()
        
        # Show feature statistics
        X = np.array(training_data)
        st.write("- **Feature Ranges:**")
        st.write(f"  - Src Rate: {X[:,0].min():.0f} - {X[:,0].max():.0f} bytes/sec")
        st.write(f"  - Dst Rate: {X[:,1].min():.0f} - {X[:,1].max():.0f} bytes/sec")
        st.write(f"  - Pkt Rate: {X[:,2].min():.1f} - {X[:,2].max():.1f} pkts/sec")
        
        status_text.text("🧠 Training ML model...")
        if S.anom.fit(training_data):
            S.trained = True
            progress_bar.empty()
            status_text.empty()
            st.success(f"✅ **Training Complete!**")
            st.write(f"- **Anomaly Threshold:** {S.anom.th:.2f}")
            st.write(f"- **Training Samples:** {S.anom.training_size}")
            st.info("💡 You can now enable 'Anomaly Detection (ML)' in the sidebar and switch to 'Active Detect' mode.")
        else:
            progress_bar.empty()
            status_text.empty()
            st.error("❌ Training failed! Insufficient data (< 50 flows).")

elif mode == "Active Detect":
    if S.sniffer and S.sniffer.running: st.success("🟢 **LIVE MONITORING ACTIVE**")
    else: st.error("🔴 **SYSTEM STOPPED**")
    c1, c2 = st.columns([3, 1])
    with c1:
        col_start, col_stop, col_ref = st.columns(3)
        if col_start.button("▶️ START", type="primary"):
            stop_all(); S.sniffer = AsyncSniffer(prn=detect_handler, store=0, iface=iface)
            S.sniffer.start(); st.rerun()
        if col_stop.button("⏹️ STOP"): stop_all(); st.rerun()
        if col_ref.button("🔄 REFRESH"): st.rerun()
        
        if S.alerts:
            st.write("### 🚨 Live Triage Console")
            h1, h2, h3, h4, h5 = st.columns([1, 1, 3, 0.5, 0.5])
            h1.write("**Time**"); h2.write("**Type**"); h3.write("**Alert Details**")
            h4.write("**✅**"); h5.write("**❌**")
            
            for a in list(S.alerts)[:15]:
                r1, r2, r3, r4, r5 = st.columns([1, 1, 3, 0.5, 0.5])
                r1.write(a["timestamp"])
                if a["category"] == "SIG": r2.markdown("🔴 `SIG`")
                else: r2.markdown("🟡 `ANOM`")
                
                # Enhanced message with bandwidth AND score
                msg = f"**{a['src_ip']}** - {a['message']}"
                if "meta" in a:
                    if "bw" in a["meta"]: 
                        msg += f" | {a['meta']['bw']/1e6:.2f} MB/s"
                    if "score" in a["meta"]:
                        msg += f" | Score: {a['meta']['score']:.1f}"
                r3.write(msg)
                
                if a["label"] is None:
                    if r4.button("✅", key=f"tp_{a['id']}", help="Confirm Threat"):
                        a["label"] = "TP"; S.tp += 1
                        S.ip_profiles[a["src_ip"]]["verdict"] = "TP"
                        logging.warning(f"CONFIRMED THREAT: {a['src_ip']} - {a['message']}")
                        st.rerun()
                    
                    if r5.button("❌", key=f"fp_{a['id']}", help="False Alarm (Learn)"):
                        a["label"] = "FP"; S.fp += 1
                        S.trusted_ips.add(a["src_ip"])
                        S.ip_profiles[a["src_ip"]]["verdict"] = "FP"
                        S.save_trusted_ips()
                        logging.info(f"LEARNED SAFE: {a['src_ip']}")
                        st.toast(f"✅ Learned: {a['src_ip']} is now trusted")
                        st.rerun()
                else:
                    if a["label"] == "TP": r4.markdown("🔴 **THREAT**")
                    else: r5.markdown("✅ **SAFE**")
        else: 
            st.info("No alerts yet. System is monitoring traffic...")
    
    with c2:
        st.metric("Active Flows", len(S.flows))
        prec = S.get_precision() * 100
        st.metric("Precision", f"{prec:.1f}%")
        st.metric("True Positives", S.tp)
        st.metric("False Positives", S.fp)

elif mode == "Demo":
    st.header("🧪 Demo / Testing")
    if st.button("Simulate Exfil Alert"): 
        log_alert("Exfil Burst (Simulated)", "192.168.1.99", "HIGH", "SIM")
        st.success("Alert generated!")
        st.rerun()
    
    if st.button("Simulate Port Scan"): 
        log_alert("Port Scan (Simulated)", "10.0.0.99", "MEDIUM", "SIM")
        st.success("Alert generated!")
        st.rerun()