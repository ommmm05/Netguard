import { useState } from 'react';
import { Code, FolderOpen, Copy, Check, Download, BookOpen } from 'lucide-react';

const tabs = ['Project Structure', 'Backend Code', 'ML Pipeline', 'Dashboard', 'Config & Deploy', 'Documentation'];

interface CodeFile {
  name: string;
  path: string;
  language: string;
  description: string;
  content: string;
}

const codeFiles: Record<string, CodeFile[]> = {
  backend: [
    {
      name: 'passive_sniffer.py', path: 'src/passive_sniffer.py', language: 'python',
      description: 'Live packet capture from network interfaces using Scapy. Passive only — no traffic injection.',
      content: `#!/usr/bin/env python3
"""
NetGuard — Passive Network Sniffer
Module: Phase 1 — Network Visibility
Engine: Scapy (passive capture only)
"""

from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, ARP, DNS, DNSQR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLS
import threading, queue, time, logging
from datetime import datetime
from collections import defaultdict
from config import Config
from db.models import PacketRecord, Session

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('NetGuard.Sniffer')

class PassiveSniffer:
    """
    Purely passive packet capture using Scapy.
    Captures on promiscuous mode — no packets injected.
    """
    def __init__(self, interface: str = None, pcap_file: str = None):
        self.interface   = interface or Config.DEFAULT_INTERFACE
        self.pcap_file   = pcap_file
        self.packet_queue = queue.Queue(maxsize=100_000)
        self.stats = defaultdict(int)
        self.running = False
        self.session = Session()

    def packet_callback(self, pkt):
        """Called for every captured packet — passive observation only."""
        try:
            self.stats['total'] += 1
            record = self._parse_packet(pkt)
            if record:
                self.packet_queue.put(record, block=False)
                self.stats[record['protocol']] += 1
        except queue.Full:
            self.stats['dropped'] += 1
        except Exception as e:
            logger.error(f"Packet parse error: {e}")

    def _parse_packet(self, pkt) -> dict | None:
        """Extract metadata from packet — no deep inspection of payload."""
        if not pkt.haslayer(IP):
            return self._handle_arp(pkt) if pkt.haslayer(ARP) else None

        ip   = pkt[IP]
        meta = {
            'timestamp'  : datetime.utcnow().isoformat(),
            'src_ip'     : ip.src,
            'dst_ip'     : ip.dst,
            'ttl'        : ip.ttl,
            'length'     : len(pkt),
            'protocol'   : 'IP',
        }

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            meta.update({
                'protocol'   : 'TCP',
                'src_port'   : tcp.sport,
                'dst_port'   : tcp.dport,
                'flags'      : str(tcp.flags),
                'window'     : tcp.window,
                'seq'        : tcp.seq,
            })
            if pkt.haslayer(TLS):
                meta['protocol'] = 'TLS'
                meta['tls_type'] = pkt[TLS].type
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            meta.update({
                'protocol' : 'UDP',
                'src_port' : udp.sport,
                'dst_port' : udp.dport,
            })
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                meta['protocol'] = 'DNS'
                meta['dns_query'] = pkt[DNSQR].qname.decode() if pkt.haslayer(DNSQR) else None

        return meta

    def _handle_arp(self, pkt) -> dict:
        arp = pkt[ARP]
        return {
            'timestamp' : datetime.utcnow().isoformat(),
            'protocol'  : 'ARP',
            'src_ip'    : arp.psrc,
            'dst_ip'    : arp.pdst,
            'src_mac'   : arp.hwsrc,
            'dst_mac'   : arp.hwdst,
            'arp_op'    : 'request' if arp.op == 1 else 'reply',
            'length'    : len(pkt),
        }

    def start_live_capture(self):
        """Start passive live capture on network interface."""
        self.running = True
        logger.info(f"Starting passive capture on {self.interface}")
        logger.info("PASSIVE MODE: No packets will be injected")
        sniff(
            iface    = self.interface,
            prn      = self.packet_callback,
            store    = False,        # Don't store in memory — stream only
            stop_filter = lambda _: not self.running
        )

    def start_pcap_replay(self, pcap_file: str = None):
        """Replay and analyze a PCAP file."""
        filepath = pcap_file or self.pcap_file
        logger.info(f"Analyzing PCAP: {filepath}")
        sniff(offline=filepath, prn=self.packet_callback, store=False)
        logger.info(f"PCAP analysis complete. Stats: {dict(self.stats)}")

    def stop(self):
        self.running = False
        logger.info(f"Sniffer stopped. Final stats: {dict(self.stats)}")

if __name__ == '__main__':
    sniffer = PassiveSniffer(interface='eth0')
    try:
        sniffer.start_live_capture()
    except KeyboardInterrupt:
        sniffer.stop()`
    },
    {
      name: 'pcap_parser.py', path: 'src/pcap_parser.py', language: 'python',
      description: 'Parse PCAP files using PyShark for detailed protocol analysis.',
      content: `#!/usr/bin/env python3
"""
NetGuard — PCAP Parser
Module: Phase 1 — Network Visibility
Engine: PyShark (TShark wrapper) for PCAP analysis
"""

import pyshark, pandas as pd, logging
from pathlib import Path
from collections import defaultdict
from typing import Generator
from config import Config

logger = logging.getLogger('NetGuard.PCAPParser')

class PCAPParser:
    """
    Parses PCAP files using PyShark for deep protocol metadata extraction.
    Used for offline forensic analysis and CICIDS2017 feature extraction.
    """
    def __init__(self, pcap_path: str):
        self.pcap_path  = Path(pcap_path)
        self.packets    = []
        self.flows      = defaultdict(list)

    def parse(self) -> pd.DataFrame:
        """Parse PCAP and return DataFrame of packet metadata."""
        logger.info(f"Parsing PCAP: {self.pcap_path}")
        cap = pyshark.FileCapture(
            str(self.pcap_path),
            display_filter='ip',       # Only IP traffic
            keep_packets=False         # Stream mode — memory efficient
        )
        records = []
        for pkt in cap:
            try:
                record = self._extract_fields(pkt)
                if record:
                    records.append(record)
            except Exception:
                pass
        cap.close()
        df = pd.DataFrame(records)
        logger.info(f"Parsed {len(df)} packets from {self.pcap_path.name}")
        return df

    def _extract_fields(self, pkt) -> dict | None:
        if not hasattr(pkt, 'ip'):
            return None
        record = {
            'timestamp'  : float(pkt.sniff_timestamp),
            'src_ip'     : pkt.ip.src,
            'dst_ip'     : pkt.ip.dst,
            'length'     : int(pkt.length),
            'protocol'   : pkt.highest_layer,
            'ttl'        : int(pkt.ip.ttl),
        }
        if hasattr(pkt, 'tcp'):
            record.update({
                'src_port' : int(pkt.tcp.srcport),
                'dst_port' : int(pkt.tcp.dstport),
                'tcp_flags': pkt.tcp.flags,
                'window'   : int(pkt.tcp.window_size),
            })
        elif hasattr(pkt, 'udp'):
            record.update({
                'src_port' : int(pkt.udp.srcport),
                'dst_port' : int(pkt.udp.dstport),
            })
        if hasattr(pkt, 'dns'):
            record['dns_query'] = getattr(pkt.dns, 'qry_name', None)
            record['dns_type']  = getattr(pkt.dns, 'qry_type', None)
        if hasattr(pkt, 'tls'):
            record['tls_sni']   = getattr(pkt.tls, 'handshake_extensions_server_name', None)
        return record

    def reconstruct_flows(self, df: pd.DataFrame) -> pd.DataFrame:
        """Reconstruct bidirectional flows from packet records."""
        df = df.sort_values('timestamp')
        df['flow_id'] = df.apply(
            lambda r: tuple(sorted([f"{r.src_ip}:{r.get('src_port',0)}",
                                     f"{r.dst_ip}:{r.get('dst_port',0)}"])) + (r.protocol,),
            axis=1
        )
        flows = df.groupby('flow_id').agg(
            pkt_count  = ('length', 'count'),
            total_bytes= ('length', 'sum'),
            duration   = ('timestamp', lambda x: x.max() - x.min()),
            src_ip     = ('src_ip', 'first'),
            dst_ip     = ('dst_ip', 'first'),
            protocol   = ('protocol', 'first'),
        ).reset_index(drop=True)
        return flows`
    },
    {
      name: 'host_mapper.py', path: 'src/host_mapper.py', language: 'python',
      description: 'Passive host discovery and network topology mapping.',
      content: `#!/usr/bin/env python3
"""
NetGuard — Host Mapper
Module: Phase 1 — Network Visibility
Discovers assets passively from observed traffic
"""

import networkx as nx
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Set, Dict, Optional
import re, logging

logger = logging.getLogger('NetGuard.HostMapper')

@dataclass
class Host:
    ip: str
    mac: Optional[str]           = None
    hostname: Optional[str]      = None
    os_hint: Optional[str]       = None     # Inferred from TTL/window
    open_ports: Set[int]         = field(default_factory=set)
    protocols: Set[str]          = field(default_factory=set)
    bytes_in: int                = 0
    bytes_out: int               = 0
    packets_in: int              = 0
    packets_out: int             = 0
    last_seen: Optional[str]     = None
    risk_score: float            = 0.0
    vendor: Optional[str]        = None     # From MAC OUI lookup

    def to_dict(self) -> dict:
        return {
            'ip': self.ip, 'mac': self.mac, 'hostname': self.hostname,
            'os': self.os_hint, 'open_ports': list(self.open_ports),
            'protocols': list(self.protocols),
            'bytes_in': self.bytes_in, 'bytes_out': self.bytes_out,
            'risk_score': self.risk_score, 'vendor': self.vendor,
        }

class HostMapper:
    """Builds and maintains network topology from passive observation."""

    OS_TTL_MAP = {
        (64, 64)   : 'Linux/macOS',
        (128, 128) : 'Windows',
        (255, 255) : 'Network Device (Cisco/HP)',
        (64, 128)  : 'Unknown',
    }

    def __init__(self):
        self.hosts: Dict[str, Host] = {}
        self.graph  = nx.DiGraph()
        self.arp_table: Dict[str, str] = {}   # IP → MAC
        self.dns_cache: Dict[str, str] = {}   # IP → hostname

    def process_packet(self, packet: dict):
        """Update host map from a single parsed packet."""
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        if not src_ip or not dst_ip:
            return

        # Ensure host records exist
        for ip in [src_ip, dst_ip]:
            if ip not in self.hosts:
                self.hosts[ip] = Host(ip=ip)
                self.graph.add_node(ip)

        size = packet.get('length', 0)
        self.hosts[src_ip].bytes_out  += size
        self.hosts[src_ip].packets_out += 1
        self.hosts[dst_ip].bytes_in   += size
        self.hosts[dst_ip].packets_in += 1
        self.hosts[src_ip].last_seen   = packet.get('timestamp')

        # Infer services from destination port
        dst_port = packet.get('dst_port')
        if dst_port:
            self.hosts[dst_ip].open_ports.add(dst_port)

        # OS fingerprint from TTL
        ttl = packet.get('ttl')
        if ttl and not self.hosts[src_ip].os_hint:
            self.hosts[src_ip].os_hint = self._infer_os(ttl)

        # Track protocols
        protocol = packet.get('protocol', 'UNKNOWN')
        self.hosts[src_ip].protocols.add(protocol)

        # ARP → MAC resolution
        if protocol == 'ARP':
            mac = packet.get('src_mac')
            if mac:
                self.arp_table[src_ip]   = mac
                self.hosts[src_ip].mac   = mac

        # DNS → hostname resolution
        if protocol == 'DNS' and packet.get('dns_query'):
            query = packet['dns_query'].rstrip('.')
            self.dns_cache[src_ip] = query
            self.hosts[src_ip].hostname = query

        # Graph edge — communication
        suspicious = self._is_suspicious(packet)
        if self.graph.has_edge(src_ip, dst_ip):
            self.graph[src_ip][dst_ip]['weight'] += size
        else:
            self.graph.add_edge(src_ip, dst_ip, weight=size,
                                protocol=protocol, suspicious=suspicious)

        self._update_risk(src_ip)

    def _infer_os(self, ttl: int) -> str:
        if ttl > 200: return 'Network Device'
        if ttl > 100: return 'Windows'
        if ttl > 50:  return 'Linux/macOS'
        return 'Unknown'

    def _is_suspicious(self, pkt: dict) -> bool:
        SUSPICIOUS_PORTS = {4444, 1337, 31337, 8888, 9999, 6667}
        return pkt.get('dst_port') in SUSPICIOUS_PORTS

    def _update_risk(self, ip: str):
        host = self.hosts[ip]
        score = 0.0
        suspicious_ports = {4444, 1337, 31337, 8888, 9999, 6667}
        if host.open_ports & suspicious_ports: score += 40
        if host.bytes_out > 500_000_000:       score += 20
        if not host.hostname:                  score += 10
        if host.packets_out > host.packets_in * 5: score += 15
        host.risk_score = min(score, 100.0)

    def get_top_talkers(self, n: int = 10) -> list:
        return sorted(
            self.hosts.values(),
            key=lambda h: h.bytes_in + h.bytes_out,
            reverse=True
        )[:n]

    def get_suspicious_hosts(self) -> list:
        return [h for h in self.hosts.values() if h.risk_score > 50]

    def export_graph(self) -> dict:
        return {
            'nodes': [h.to_dict() for h in self.hosts.values()],
            'edges': [{'src': u, 'dst': v, **d}
                      for u, v, d in self.graph.edges(data=True)],
        }`
    },
  ],
  ml: [
    {
      name: 'preprocess.py', path: 'ml/preprocess.py', language: 'python',
      description: 'CICIDS2017 dataset loading, cleaning, feature engineering, and train/test split.',
      content: `#!/usr/bin/env python3
"""
NetGuard — Data Preprocessor
Module: Phase 2 — AI Threat Detection
Dataset: CICIDS2017
"""

import pandas as pd, numpy as np, logging
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from imblearn.over_sampling import SMOTE
from config import Config

logger = logging.getLogger('NetGuard.Preprocess')

CICIDS_LABEL_MAP = {
    'BENIGN'             : 'Benign',
    'DoS Hulk'           : 'DoS',
    'DoS GoldenEye'      : 'DoS',
    'DoS slowloris'      : 'DoS',
    'DoS Slowhttptest'   : 'DoS',
    'DDoS'               : 'DDoS',
    'PortScan'           : 'Port Scan',
    'FTP-Patator'        : 'Brute Force',
    'SSH-Patator'        : 'Brute Force',
    'Web Attack'         : 'Web Attack',
    'Bot'                : 'Botnet',
    'Infiltration'       : 'Infiltration',
}

# 78 features used from CICIDS2017
SELECTED_FEATURES = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
    'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
    'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
    'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length.1', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
    'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
    'Destination Port', 'Protocol',
    # Engineered features
    'bytes_per_packet', 'pkt_ratio_fwd_bwd', 'flag_ratio_syn_ack',
    'iat_variance_ratio', 'pkt_size_entropy', 'dst_port_risk_score',
    'connection_rate_1min', 'unique_dst_ports_1min',
    'payload_entropy', 'duration_bytes_ratio', 'syn_only_ratio', 'idle_active_ratio',
]

class CICIDSPreprocessor:
    def __init__(self, data_dir: str = Config.DATA_DIR):
        self.data_dir = Path(data_dir)
        self.scaler   = StandardScaler()
        self.encoder  = LabelEncoder()
        self.feature_cols = SELECTED_FEATURES

    def load_dataset(self) -> pd.DataFrame:
        """Load all CICIDS2017 CSV files from data directory."""
        dfs = []
        for csv_file in self.data_dir.glob('*.csv'):
            logger.info(f"Loading {csv_file.name}")
            df = pd.read_csv(csv_file, low_memory=False)
            df.columns = df.columns.str.strip()
            dfs.append(df)
        df = pd.concat(dfs, ignore_index=True)
        logger.info(f"Loaded {len(df):,} records from {len(dfs)} files")
        return df

    def clean(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove NaN, Inf, and map labels."""
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna(subset=self.feature_cols + [' Label'], how='any')
        df[' Label'] = df[' Label'].map(CICIDS_LABEL_MAP).fillna('Other')
        logger.info(f"After cleaning: {len(df):,} records")
        return df

    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add 12 engineered features."""
        df['bytes_per_packet']     = df['Total Length of Fwd Packets'] / (df['Total Fwd Packets'] + 1)
        df['pkt_ratio_fwd_bwd']    = df['Total Fwd Packets'] / (df['Total Backward Packets'] + 1)
        df['flag_ratio_syn_ack']   = df['SYN Flag Count'] / (df['ACK Flag Count'] + 1)
        df['iat_variance_ratio']   = df['Flow IAT Std'] / (df['Flow IAT Mean'] + 1e-6)
        df['pkt_size_entropy']     = np.log1p(df['Packet Length Std'] / (df['Packet Length Mean'] + 1))
        df['duration_bytes_ratio'] = df['Flow Duration'] / (df['Flow Bytes/s'] + 1)
        df['syn_only_ratio']       = df['SYN Flag Count'] / (df['FIN Flag Count'] + df['ACK Flag Count'] + 1)
        df['idle_active_ratio']    = df['Idle Mean'] / (df['Active Mean'] + 1)
        df['dst_port_risk_score']  = df['Destination Port'].apply(
            lambda p: 100 if p in {4444,1337,31337} else 50 if p in {21,23,445} else 0
        )
        df['payload_entropy']      = df['Average Packet Size'].apply(lambda x: min(x / 1500, 1.0))
        df['connection_rate_1min'] = df['Flow Packets/s']
        df['unique_dst_ports_1min'] = 1
        return df

    def prepare(self) -> tuple:
        """Full pipeline: load → clean → engineer → split → scale → SMOTE."""
        df    = self.load_dataset()
        df    = self.clean(df)
        df    = self.engineer_features(df)
        X     = df[self.feature_cols].values
        y     = self.encoder.fit_transform(df[' Label'].values)
        X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
        X_tr  = self.scaler.fit_transform(X_tr)
        X_te  = self.scaler.transform(X_te)
        sm    = SMOTE(random_state=42, k_neighbors=5)
        X_tr, y_tr = sm.fit_resample(X_tr, y_tr)
        logger.info(f"Train: {X_tr.shape}, Test: {X_te.shape}")
        return X_tr, X_te, y_tr, y_te`
    },
    {
      name: 'train_model.py', path: 'ml/train_model.py', language: 'python',
      description: 'Train Random Forest, XGBoost, and Isolation Forest models.',
      content: `#!/usr/bin/env python3
"""
NetGuard — Model Trainer
Module: Phase 2 — AI Threat Detection
Models: Random Forest, XGBoost, Isolation Forest
"""

import joblib, logging, json
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, roc_auc_score
from preprocess import CICIDSPreprocessor
from config import Config

logger = logging.getLogger('NetGuard.Trainer')
MODEL_DIR = Path('models/')
MODEL_DIR.mkdir(exist_ok=True)

def train_random_forest(X_train, y_train) -> RandomForestClassifier:
    logger.info("Training Random Forest (200 estimators)...")
    rf = RandomForestClassifier(
        n_estimators     = 200,
        max_depth        = None,
        min_samples_split= 5,
        class_weight     = 'balanced',
        n_jobs           = -1,
        random_state     = 42,
        verbose          = 1,
    )
    rf.fit(X_train, y_train)
    joblib.dump(rf, MODEL_DIR / 'random_forest.pkl')
    logger.info("Random Forest saved → models/random_forest.pkl")
    return rf

def train_xgboost(X_train, y_train) -> XGBClassifier:
    logger.info("Training XGBoost (150 estimators)...")
    xgb = XGBClassifier(
        n_estimators     = 150,
        max_depth        = 6,
        learning_rate    = 0.1,
        subsample        = 0.8,
        colsample_bytree = 0.8,
        objective        = 'multi:softprob',
        eval_metric      = 'mlogloss',
        use_label_encoder= False,
        n_jobs           = -1,
        random_state     = 42,
        verbosity        = 1,
    )
    xgb.fit(
        X_train, y_train,
        eval_set = [(X_train, y_train)],
        verbose  = 50,
    )
    xgb.save_model(str(MODEL_DIR / 'xgboost.json'))
    logger.info("XGBoost saved → models/xgboost.json")
    return xgb

def train_isolation_forest(X_train) -> IsolationForest:
    logger.info("Training Isolation Forest for anomaly detection...")
    iso = IsolationForest(
        n_estimators = 100,
        contamination= 0.05,    # Expect 5% anomalies
        max_samples  = 'auto',
        random_state = 42,
        n_jobs       = -1,
        verbose      = 1,
    )
    iso.fit(X_train)
    joblib.dump(iso, MODEL_DIR / 'isolation_forest.pkl')
    logger.info("Isolation Forest saved → models/isolation_forest.pkl")
    return iso

def evaluate_model(model, X_test, y_test, class_names, model_name):
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test) if hasattr(model, 'predict_proba') else None
    report  = classification_report(y_test, y_pred, target_names=class_names, output_dict=True)
    roc     = roc_auc_score(y_test, y_proba, multi_class='ovr') if y_proba is not None else None
    logger.info(f"\\n{model_name} Evaluation:")
    logger.info(f"  Accuracy : {report['accuracy']:.4f}")
    logger.info(f"  F1 Macro : {report['macro avg']['f1-score']:.4f}")
    if roc: logger.info(f"  ROC-AUC  : {roc:.4f}")
    return {'report': report, 'roc_auc': roc}

if __name__ == '__main__':
    preprocessor = CICIDSPreprocessor()
    X_tr, X_te, y_tr, y_te = preprocessor.prepare()
    class_names = list(preprocessor.encoder.classes_)

    rf  = train_random_forest(X_tr, y_tr)
    xgb = train_xgboost(X_tr, y_tr)
    iso = train_isolation_forest(X_tr)

    rf_metrics  = evaluate_model(rf,  X_te, y_te, class_names, 'Random Forest')
    xgb_metrics = evaluate_model(xgb, X_te, y_te, class_names, 'XGBoost')

    json.dump({'random_forest': rf_metrics, 'xgboost': xgb_metrics},
              open(MODEL_DIR / 'evaluation_results.json', 'w'), indent=2)
    logger.info("All models trained and evaluated successfully.")`
    },
    {
      name: 'shap_explainer.py', path: 'forensics/shap_explainer.py', language: 'python',
      description: 'SHAP TreeExplainer for per-prediction feature attribution.',
      content: `#!/usr/bin/env python3
"""
NetGuard — SHAP Explainer
Module: Phase 3 — Forensics & Incident Intelligence
Library: SHAP TreeExplainer
"""

import shap, joblib, numpy as np, pandas as pd
import matplotlib.pyplot as plt
import logging
from pathlib import Path
from xgboost import XGBClassifier

logger = logging.getLogger('NetGuard.SHAP')
MODEL_DIR = Path('models/')

class NetGuardSHAPExplainer:
    """
    TreeSHAP-based explainability for XGBoost and Random Forest.
    Provides per-prediction feature attribution for alert reasoning.
    """
    def __init__(self, model_type: str = 'xgboost'):
        self.model_type   = model_type
        self.model        = self._load_model()
        self.explainer    = shap.TreeExplainer(self.model)
        self.feature_names = []  # Set from preprocessor

    def _load_model(self):
        if self.model_type == 'xgboost':
            model = XGBClassifier()
            model.load_model(str(MODEL_DIR / 'xgboost.json'))
        else:
            model = joblib.load(MODEL_DIR / 'random_forest.pkl')
        logger.info(f"Loaded {self.model_type} model for SHAP analysis")
        return model

    def explain_prediction(self, features: np.ndarray,
                           class_names: list = None) -> dict:
        """
        Compute SHAP values for a single prediction.
        Returns feature contributions and base value.
        """
        shap_values = self.explainer.shap_values(features)
        prediction  = self.model.predict(features)[0]
        confidence  = self.model.predict_proba(features).max() * 100

        # For multi-class: take SHAP for predicted class
        if isinstance(shap_values, list):
            class_shap = shap_values[prediction][0]
        else:
            class_shap = shap_values[0]

        # Build feature attribution dict
        attributions = []
        for fname, fval, sval in zip(
            self.feature_names, features[0], class_shap
        ):
            attributions.append({
                'feature'  : fname,
                'value'    : float(fval),
                'shap'     : float(sval),
                'direction': 'harmful' if sval > 0 else 'benign',
                'abs_shap' : abs(float(sval)),
            })

        attributions.sort(key=lambda x: x['abs_shap'], reverse=True)

        return {
            'prediction'  : class_names[prediction] if class_names else str(prediction),
            'confidence'  : round(confidence, 2),
            'base_value'  : float(self.explainer.expected_value[prediction]
                                  if isinstance(self.explainer.expected_value, list)
                                  else self.explainer.expected_value),
            'top_features': attributions[:10],
            'all_features': attributions,
        }

    def plot_waterfall(self, features: np.ndarray, output_path: str = None,
                       class_names: list = None, max_display: int = 10):
        """Generate SHAP waterfall plot for a single prediction."""
        shap_values = self.explainer(features)
        prediction  = int(self.model.predict(features)[0])

        # For multi-class models
        if len(shap_values.values.shape) == 3:
            sv = shap_values[0, :, prediction]
        else:
            sv = shap_values[0]

        plt.figure(figsize=(10, 6))
        shap.plots.waterfall(sv, max_display=max_display, show=False)
        plt.title(f"SHAP Waterfall — {class_names[prediction] if class_names else 'Prediction'}", fontsize=13)
        plt.tight_layout()
        if output_path:
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            logger.info(f"Waterfall plot saved → {output_path}")
        return plt.gcf()

    def global_feature_importance(self, X_sample: np.ndarray) -> pd.DataFrame:
        """Compute global feature importance across sample set."""
        shap_values = self.explainer.shap_values(X_sample)
        if isinstance(shap_values, list):
            mean_abs = np.mean([np.abs(sv).mean(axis=0) for sv in shap_values], axis=0)
        else:
            mean_abs = np.abs(shap_values).mean(axis=0)
        df = pd.DataFrame({
            'feature'   : self.feature_names,
            'importance': mean_abs,
        }).sort_values('importance', ascending=False)
        return df`
    },
  ],
  config: [
    {
      name: 'requirements.txt', path: 'requirements.txt', language: 'text',
      description: 'All Python dependencies for the complete NetGuard platform.',
      content: `# NetGuard — Python Dependencies
# Phase 1: Network Visibility
scapy==2.5.0
pyshark==0.6
netifaces==0.11.0
dpkt==1.9.8
networkx==3.2.1

# Phase 2: AI/ML
numpy==1.26.2
pandas==2.1.4
scikit-learn==1.3.2
xgboost==2.0.2
imbalanced-learn==0.11.0
joblib==1.3.2

# Phase 3: Forensics
shap==0.44.0
openai==1.6.1          # LLM API
transformers==4.36.0   # Local LLM fallback
torch==2.1.1           # Mistral-7B inference
reportlab==4.0.7       # PDF generation
fpdf2==2.7.6

# Dashboard
plotly==5.18.0
dash==2.14.2
dash-bootstrap-components==1.5.0

# Database
sqlalchemy==2.0.23
alembic==1.12.1
psycopg2-binary==2.9.9  # PostgreSQL
# sqlite3 — built-in Python

# API / Utils
flask==3.0.0
flask-cors==4.0.0
python-dotenv==1.0.0
pydantic==2.5.2
loguru==0.7.2
tqdm==4.66.1
matplotlib==3.8.2
seaborn==0.13.0

# Testing
pytest==7.4.3
pytest-cov==4.1.0
pytest-asyncio==0.21.1`
    },
    {
      name: 'docker-compose.yml', path: 'docker-compose.yml', language: 'yaml',
      description: 'Docker Compose configuration for full platform deployment.',
      content: `version: '3.9'

services:
  netguard-backend:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: netguard-backend
    ports:
      - "8050:8050"   # Plotly Dash
      - "5000:5000"   # Flask REST API
    volumes:
      - ./data:/app/data
      - ./models:/app/models
      - ./pcaps:/app/pcaps
      - ./logs:/app/logs
    environment:
      - NETGUARD_ENV=production
      - DATABASE_URL=postgresql://netguard:password@postgres:5432/netguard
      - OPENAI_API_KEY=\${OPENAI_API_KEY}
      - CAPTURE_INTERFACE=eth0
      - LOG_LEVEL=INFO
    network_mode: host      # Required for packet capture
    cap_add:
      - NET_ADMIN           # Required for promiscuous mode
      - NET_RAW
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:15-alpine
    container_name: netguard-db
    environment:
      POSTGRES_DB: netguard
      POSTGRES_USER: netguard
      POSTGRES_PASSWORD: password
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./db/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    container_name: netguard-cache
    ports:
      - "6379:6379"
    volumes:
      - redisdata:/data

  netguard-ml-trainer:
    build:
      context: .
      dockerfile: Dockerfile.ml
    container_name: netguard-trainer
    volumes:
      - ./data:/app/data
      - ./models:/app/models
    command: python ml/train_model.py
    profiles:
      - train              # Run with: docker-compose --profile train up

volumes:
  pgdata:
  redisdata:`
    },
    {
      name: '.env.example', path: '.env.example', language: 'bash',
      description: 'Environment variable template for NetGuard configuration.',
      content: `# NetGuard Environment Configuration
# Copy to .env and fill in values

# ─── Core ──────────────────────────────────────────
NETGUARD_ENV=development           # development | production
SECRET_KEY=your-secret-key-here
DEBUG=True

# ─── Network Capture ──────────────────────────────
CAPTURE_INTERFACE=eth0             # Network interface to monitor
PCAP_DIR=./data/pcaps              # Directory for PCAP files
CAPTURE_BUFFER_SIZE=65536          # Packet buffer size (bytes)
PASSIVE_ONLY=true                  # NEVER set to false in production

# ─── Database ──────────────────────────────────────
DATABASE_URL=sqlite:///./netguard.db
# DATABASE_URL=postgresql://user:pass@localhost:5432/netguard

# ─── AI/ML ────────────────────────────────────────
MODEL_DIR=./models
CICIDS_DATA_DIR=./data/cicids2017
ML_CONFIDENCE_THRESHOLD=0.85      # Min confidence to raise alert
ISOLATION_FOREST_CONTAMINATION=0.05

# ─── LLM Integration ──────────────────────────────
OPENAI_API_KEY=sk-...              # GPT-4 API key
OPENAI_MODEL=gpt-4-turbo-preview
LLM_FALLBACK=mistral               # mistral | llama | none
LOCAL_LLM_PATH=./models/mistral-7b.gguf

# ─── SHAP ──────────────────────────────────────────
SHAP_MAX_FEATURES=10
SHAP_SAMPLE_SIZE=1000

# ─── Dashboard ────────────────────────────────────
DASH_PORT=8050
DASH_HOST=0.0.0.0
DASH_DEBUG=True
UPDATE_INTERVAL_MS=5000            # Live update interval

# ─── Alerting ──────────────────────────────────────
ALERT_WEBHOOK_URL=                 # Slack/Teams webhook
SMTP_HOST=                         # Email alerting
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=`
    },
  ],
};

const folderStructure = `netguard/
├── src/                          # Phase 1: Network Visibility
│   ├── passive_sniffer.py        # Scapy live capture engine
│   ├── pcap_parser.py            # PyShark PCAP file analysis
│   ├── feature_extractor.py      # 78-feature extraction
│   ├── host_mapper.py            # Asset discovery & topology
│   └── protocol_analyzer.py     # DNS/ARP/DHCP/TLS metadata
│
├── ml/                           # Phase 2: AI Threat Detection
│   ├── preprocess.py             # CICIDS2017 preprocessing
│   ├── train_model.py            # RF + XGBoost + IsoForest
│   ├── inference.py              # Real-time flow classification
│   ├── anomaly_detection.py      # Isolation Forest pipeline
│   └── evaluate.py               # Metrics & confusion matrix
│
├── forensics/                    # Phase 3: Forensic Intelligence
│   ├── shap_explainer.py         # TreeSHAP attributions
│   ├── llm_reporter.py           # GPT-4 / Mistral reports
│   ├── forensic_export.py        # PDF / CSV / JSON export
│   └── analyst_assistant.py      # Interactive chat assistant
│
├── dashboard/                    # Plotly Dash SOC UI
│   ├── app.py                    # Main Dash application
│   └── pages/
│       ├── overview.py           # SOC Overview
│       ├── visibility.py         # Network Visibility
│       ├── detection.py          # Threat Detection
│       ├── alerts.py             # Alert Center
│       ├── forensics.py          # Forensics & Intel
│       └── settings.py           # Configuration
│
├── db/                           # Database Layer
│   ├── models.py                 # SQLAlchemy ORM models
│   ├── db_init.py                # Schema creation & seeding
│   └── migrations/               # Alembic migrations
│
├── tests/                        # Test Suite
│   ├── test_sniffer.py
│   ├── test_pcap_parser.py
│   ├── test_feature_extractor.py
│   ├── test_ml_pipeline.py
│   ├── test_shap_explainer.py
│   └── fixtures/
│       └── sample_traffic.pcap
│
├── data/
│   ├── cicids2017/               # CICIDS2017 CSV files
│   ├── pcaps/                    # Captured/test PCAPs
│   └── threat_intel/             # IP/domain blacklists
│
├── models/                       # Trained ML artifacts
│   ├── random_forest.pkl
│   ├── xgboost.json
│   ├── isolation_forest.pkl
│   ├── scaler.pkl
│   ├── label_encoder.pkl
│   └── evaluation_results.json
│
├── config.py                     # Central configuration
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment template
├── Dockerfile                    # Container build
├── docker-compose.yml            # Full stack deployment
├── setup.sh                      # One-command setup
├── run.sh                        # Start platform
└── README.md                     # Documentation`;

function CodeBlock({ code, language }: { code: string; language: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="relative group">
      <div className="flex items-center justify-between px-3 py-1.5 bg-slate-800 border-b border-slate-700/60 rounded-t-lg">
        <span className="text-xs text-slate-400 font-mono">{language}</span>
        <button onClick={copy} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors">
          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <pre className="p-4 bg-slate-950 rounded-b-lg overflow-x-auto text-xs font-mono text-slate-300 leading-relaxed max-h-96 overflow-y-auto">
        <code>{code}</code>
      </pre>
    </div>
  );
}

export default function Codebase() {
  const [activeTab, setActiveTab] = useState(0);
  const [activeFile, setActiveFile] = useState(0);
  const [activeSection, setActiveSection] = useState<'backend' | 'ml' | 'config'>('backend');

  const currentFiles = codeFiles[activeSection];
  const currentFile = currentFiles[activeFile];

  const docSections = [
    {
      title: '🏗️ System Architecture',
      content: `NetGuard is a 3-phase integrated SOC platform:\n\n• Phase 1 (Visibility): Scapy passive sniffer → PyShark PCAP parser → Host Mapper → Protocol Analyzer → SQLite/PostgreSQL\n• Phase 2 (Detection): Feature Extractor → CICIDS2017 → Preprocessor → RF+XGBoost+IsoForest → Inference Engine\n• Phase 3 (Forensics): SHAP Explainer → LLM Reporter → Analyst Assistant → Export Engine\n\nAll phases feed into a unified Plotly Dash SOC Dashboard.`
    },
  ];

  return (
    <div className="p-4 md:p-6 space-y-4 overflow-auto h-full">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Code className="w-5 h-5 text-yellow-400" /> Project Codebase — Implementation Ready
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">Complete source code scaffold · Copy · Implement · Deploy</p>
        </div>
        <div className="flex gap-2">
          <button className="flex items-center gap-1.5 px-3 py-1.5 bg-yellow-500/10 border border-yellow-500/20 rounded-lg text-xs text-yellow-400 hover:bg-yellow-500/20">
            <Download className="w-3 h-3" /> Download ZIP
          </button>
        </div>
      </div>

      {/* Main tabs */}
      <div className="flex gap-1 bg-slate-900/60 border border-slate-700/60 rounded-xl p-1 flex-wrap">
        {tabs.map((tab, i) => (
          <button key={tab} onClick={() => setActiveTab(i)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${activeTab === i ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'}`}>
            {tab}
          </button>
        ))}
      </div>

      {activeTab === 0 && (
        <div className="bg-slate-900/80 border border-slate-700/60 rounded-xl p-4 md:p-6">
          <div className="flex items-center gap-2 mb-3">
            <FolderOpen className="w-4 h-4 text-yellow-400" />
            <h4 className="text-sm font-semibold text-white">Complete Folder Structure</h4>
          </div>
          <pre className="text-xs font-mono text-slate-300 leading-relaxed overflow-x-auto">
            {folderStructure}
          </pre>
        </div>
      )}

      {(activeTab === 1 || activeTab === 2 || activeTab === 4) && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          <div className="lg:col-span-1 space-y-2">
            {activeTab === 1 && (
              <div className="flex gap-1 flex-wrap mb-2">
                {(['backend', 'ml', 'config'] as const).map(s => (
                  <button key={s} onClick={() => { setActiveSection(s); setActiveFile(0); }}
                    className={`px-2 py-1 rounded text-xs ${activeSection === s ? 'bg-yellow-500/20 text-yellow-400' : 'bg-slate-800 text-slate-400'}`}>
                    {s}
                  </button>
                ))}
              </div>
            )}
            {currentFiles.map((f, i) => (
              <button key={f.name} onClick={() => setActiveFile(i)}
                className={`w-full text-left p-3 rounded-lg border transition-all text-xs ${activeFile === i ? 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400' : 'border-slate-700/60 bg-slate-900/60 text-slate-400 hover:text-slate-200'}`}>
                <p className="font-mono font-semibold">{f.name}</p>
                <p className="text-slate-500 mt-0.5 line-clamp-2">{f.description}</p>
              </button>
            ))}
          </div>
          <div className="lg:col-span-3 space-y-3">
            {currentFile && (
              <>
                <div className="bg-slate-800/60 border border-slate-700/60 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-semibold text-white font-mono">{currentFile.path}</p>
                      <p className="text-xs text-slate-400 mt-0.5">{currentFile.description}</p>
                    </div>
                    <span className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded font-mono">{currentFile.language}</span>
                  </div>
                </div>
                <CodeBlock code={currentFile.content} language={currentFile.language} />
              </>
            )}
          </div>
        </div>
      )}

      {activeTab === 3 && (
        <div className="bg-slate-900/80 border border-slate-700/60 rounded-xl p-4">
          <h4 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
            <BookOpen className="w-4 h-4 text-yellow-400" /> Plotly Dash Dashboard Structure
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              { file: 'dashboard/app.py', desc: 'Main Dash app, routing, sidebar, live callbacks', key: 'Dash, dcc, html, Input, Output, State' },
              { file: 'dashboard/pages/overview.py', desc: 'SOC Overview: KPI cards, traffic timeline, attack distribution', key: 'dcc.Graph, plotly.express, dcc.Interval' },
              { file: 'dashboard/pages/visibility.py', desc: 'Network map, host table, session flows, DNS, ARP, bandwidth', key: 'cytoscape, DataTable, plotly go' },
              { file: 'dashboard/pages/detection.py', desc: 'ML metrics, confusion matrix, feature importance, live inference', key: 'plotly go heatmap, bar chart, radar' },
              { file: 'dashboard/pages/alerts.py', desc: 'Prioritized alert table, SHAP mini-chart, remediation panel', key: 'DataTable, dcc.Store, callbacks' },
              { file: 'dashboard/pages/forensics.py', desc: 'SHAP waterfall, timeline, LLM report, IOC list, export', key: 'shap.plots, html.Iframe, dcc.Download' },
              { file: 'dashboard/pages/settings.py', desc: 'Interface config, model params, LLM settings, alert thresholds', key: 'dcc.Input, dcc.Checklist, dbc.Form' },
            ].map((p, i) => (
              <div key={i} className="p-3 bg-slate-800/60 rounded-lg border border-slate-700/60">
                <p className="text-xs font-mono text-yellow-400 font-semibold">{p.file}</p>
                <p className="text-xs text-slate-300 mt-1">{p.desc}</p>
                <p className="text-xs text-slate-500 mt-1 font-mono">{p.key}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 5 && (
        <div className="space-y-4">
          {docSections.map((s, i) => (
            <div key={i} className="bg-slate-900/80 border border-slate-700/60 rounded-xl p-4 md:p-6">
              <h4 className="text-sm font-bold text-white mb-3">{s.title}</h4>
              <pre className="text-xs text-slate-300 whitespace-pre-wrap leading-relaxed font-sans">{s.content}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
