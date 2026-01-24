"""
Merger - Combina logs de Zeek con eventos de Docker y calcula todas las features
Genera filas en formato dataset listas para el modelo

ACTUALIZADO: Usa nuevo pipeline realtime para generar ventanas correctas
"""

import os
import json
import time
import logging
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import deque
from dataclasses import dataclass, asdict, field
import statistics
import pandas as pd

import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel

# Sliding Window (legacy)
from sliding_window import SlidingWindowAnalyzer, WindowConfig

# NUEVO: Pipeline realtime
from realtime_pipeline import ConsulPoisoningPipeline
from realtime_dataset_generator import ZeekConnection, ZeekSSL, DockerEvent

# ============================================
# CONFIGURACIÓN
# ============================================

# Historial de windows generadas (últimas 100 para visualización)
RECENT_WINDOWS = deque(maxlen=100)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
ZEEK_LOG_DIR = os.getenv("ZEEK_LOG_DIR", "/zeek_logs")
LOG_SHIPPER_URL = os.getenv("LOG_SHIPPER_URL", "http://log-shipper:8081")
ADS_SERVER_URL = os.getenv("ADS_SERVER_URL", "http://ads-server:8080/predict")
PROCESS_INTERVAL = int(os.getenv("PROCESS_INTERVAL_SECONDS", "5"))

# Configuración de ventanas - SIN solapamiento
WINDOW_TIMEOUT_SECONDS = float(os.getenv("WINDOW_TIMEOUT_SECONDS", "15"))  # Timeout para cerrar ventana

# Consul configuration (HTTPS)
CONSUL_HOST = os.getenv("CONSUL_HOST", "10.1.11.40")
CONSUL_PORT = os.getenv("CONSUL_PORT", "8501")
CONSUL_SCHEME = os.getenv("CONSUL_SCHEME", "https")
CONSUL_BASE_URL = f"{CONSUL_SCHEME}://{CONSUL_HOST}:{CONSUL_PORT}/v1"

# Logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("merger")

app = FastAPI(
    title="Merger",
    description="Combina Zeek logs + Docker events, calcula features",
    version="1.0.0"
)

# ============================================
# MODELOS
# ============================================

@dataclass
class ZeekConnection:
    """Conexión parseada de conn.log"""
    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str = "tcp"
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    conn_state: str = "SF"
    orig_pkts: int = 0
    resp_pkts: int = 0
    missed_bytes: int = 0

@dataclass
class ZeekSSL:
    """Datos SSL parseados de ssl.log"""
    ts: float
    uid: str
    version: str = "TLSv12"
    cipher: str = ""
    server_name: str = ""
    ja3: str = ""
    ja3s: str = ""
    resumed: bool = False
    established: bool = True

@dataclass
class DatasetRow:
    """Fila del dataset con todas las features calculadas"""
    # Identificadores
    ts: float
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    
    # Métricas de conexión
    orig_bytes: float
    resp_bytes: float
    bytes_ratio: float
    duration: float
    duration_zscore: float
    conn_state_encoded: int
    
    # Features temporales
    conn_interval: float
    time_since_last_conn: Optional[float]
    conn_count_10s: int
    conn_count_60s: int
    conn_count_300s: int
    interval_stddev: float
    burst_score: float
    total_conn_from_ip: int
    hour_of_day: int
    
    # Features JA3
    ja3: str
    ja3_frequency: int
    ja3_is_known: int
    ja3_behavior_score: float
    unique_ja3_from_ip: int
    
    # Features de IP
    is_known_ip: int
    ip_first_seen_hours_ago: float
    
    # Features de patrones
    recon_pattern_score: float
    recent_activity_score: float
    
    # Features de Docker
    recent_docker_event: int
    time_since_container_start: float

# ============================================
# ESTADO DEL MERGER
# ============================================

class MergerState:
    def __init__(self):
        # Historial de conexiones por IP (para calcular features temporales)
        self.connections_by_ip: Dict[str, deque] = {}
        # Historial de todas las conexiones (para zscore)
        self.all_durations: deque = deque(maxlen=1000)
        # Conteo de JA3
        self.ja3_counts: Dict[str, int] = {}
        # Primera vez vista cada IP
        self.ip_first_seen: Dict[str, float] = {}
        # JA3 por IP
        self.ja3_by_ip: Dict[str, set] = {}
        # Última posición leída de cada log
        self.log_positions: Dict[str, int] = {}
        # Headers de los logs
        self.log_headers: Dict[str, List[str]] = {}
        # Conexiones pendientes de SSL (por uid)
        self.pending_ssl: Dict[str, ZeekSSL] = {}
        # Filas generadas (buffer para enviar)
        self.output_buffer: deque = deque(maxlen=1000)
        # Cache de info de contenedores (IP -> {start_time, container_name})
        self.container_info: Dict[str, dict] = {}
        # Estadísticas
        self.stats = {
            "connections_processed": 0,
            "rows_generated": 0,
            "rows_sent": 0,
            "errors": 0
        }
        # NUEVO: Tracking para cerrar ventana cuando cambia IP
        self.last_seen_ip: Optional[str] = None
        self.last_ip_change_time: float = 0.0
        self.pending_window_ip: Optional[str] = None  # IP con ventana pendiente de enviar
        # NUEVO: Tracking de última conexión para timeout de ventana
        self.last_connection_time: float = 0.0
        self.window_sent_for_current_ip: bool = False  # Evitar envíos duplicados

state = MergerState()

# NUEVO: Pipeline realtime para generar ventanas SIN solapamiento
from realtime_window_generator import WindowConfig as RealtimeWindowConfig
realtime_config = RealtimeWindowConfig(
    timeout_seconds=WINDOW_TIMEOUT_SECONDS,
    min_connections=1
)
realtime_pipeline = ConsulPoisoningPipeline(realtime_config)

# ============================================
# PARSERS DE LOGS ZEEK
# ============================================

def parse_zeek_header(line: str) -> Optional[List[str]]:
    """Parsea línea de header de Zeek"""
    if line.startswith("#fields"):
        return line.strip().split("\t")[1:]
    return None

def parse_zeek_value(value: str, field_name: str) -> any:
    """Convierte valor de Zeek al tipo correcto"""
    if value == "-" or value == "(empty)":
        return None
    if value == "T":
        return True
    if value == "F":
        return False
    
    # Intentar conversión numérica
    try:
        if "." in value and field_name in ["ts", "duration"]:
            return float(value)
        elif field_name in ["orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", 
                           "missed_bytes", "id.orig_p", "id.resp_p"]:
            return int(value)
        else:
            return value
    except ValueError:
        return value

def parse_conn_log_line(line: str, headers: List[str]) -> Optional[ZeekConnection]:
    """Parsea una línea de conn.log"""
    if line.startswith("#"):
        return None
    
    fields = line.strip().split("\t")
    if len(fields) != len(headers):
        return None
    
    data = {}
    for header, value in zip(headers, fields):
        data[header] = parse_zeek_value(value, header)
    
    try:
        return ZeekConnection(
            ts=data.get("ts", 0.0) or 0.0,
            uid=data.get("uid", ""),
            orig_h=data.get("id.orig_h", ""),
            orig_p=data.get("id.orig_p", 0) or 0,
            resp_h=data.get("id.resp_h", ""),
            resp_p=data.get("id.resp_p", 0) or 0,
            proto=data.get("proto", "tcp"),
            duration=data.get("duration", 0.0) or 0.0,
            orig_bytes=data.get("orig_bytes", 0) or 0,
            resp_bytes=data.get("resp_bytes", 0) or 0,
            conn_state=data.get("conn_state", "SF"),
            orig_pkts=data.get("orig_pkts", 0) or 0,
            resp_pkts=data.get("resp_pkts", 0) or 0,
            missed_bytes=data.get("missed_bytes", 0) or 0
        )
    except Exception as e:
        logger.error(f"Error parseando conn.log: {e}")
        return None

def parse_ssl_log_line(line: str, headers: List[str]) -> Optional[ZeekSSL]:
    """Parsea una línea de ssl.log"""
    if line.startswith("#"):
        return None
    
    fields = line.strip().split("\t")
    if len(fields) != len(headers):
        return None
    
    data = {}
    for header, value in zip(headers, fields):
        data[header] = parse_zeek_value(value, header)
    
    try:
        return ZeekSSL(
            ts=data.get("ts", 0.0) or 0.0,
            uid=data.get("uid", ""),
            version=data.get("version", "TLSv12") or "TLSv12",
            cipher=data.get("cipher", "") or "",
            server_name=data.get("server_name", "") or "",
            ja3=data.get("ja3", "") or "",
            ja3s=data.get("ja3s", "") or "",
            resumed=data.get("resumed", False) or False,
            established=data.get("established", True)
        )
    except Exception as e:
        logger.error(f"Error parseando ssl.log: {e}")
        return None

# ============================================
# CÁLCULO DE FEATURES
# ============================================

def encode_conn_state(conn_state: str) -> int:
    """Codifica el estado de conexión"""
    states = {
        "S0": 0, "S1": 1, "SF": 2, "REJ": 3,
        "S2": 4, "S3": 5, "RSTO": 6, "RSTR": 7,
        "RSTOS0": 8, "RSTRH": 9, "SH": 10, "SHR": 11,
        "OTH": 12
    }
    return states.get(conn_state, 3)  # Default SF

def calculate_duration_zscore(duration: float) -> float:
    """Calcula z-score de la duración"""
    if len(state.all_durations) < 2:
        return 0.0
    
    mean = statistics.mean(state.all_durations)
    stdev = statistics.stdev(state.all_durations)
    
    if stdev == 0:
        return 0.0
    
    return (duration - mean) / stdev

def get_connections_in_window(ip: str, current_ts: float, window_seconds: float) -> List[float]:
    """Obtiene timestamps de conexiones en una ventana temporal"""
    if ip not in state.connections_by_ip:
        return []
    
    cutoff = current_ts - window_seconds
    return [ts for ts in state.connections_by_ip[ip] if ts >= cutoff]

def calculate_temporal_features(ip: str, current_ts: float) -> Dict:
    """Calcula features temporales para una IP"""
    conns = state.connections_by_ip.get(ip, deque())
    
    # Conexiones en diferentes ventanas
    conn_10s = len(get_connections_in_window(ip, current_ts, 10))
    conn_60s = len(get_connections_in_window(ip, current_ts, 60))
    conn_300s = len(get_connections_in_window(ip, current_ts, 300))
    
    # Intervalo desde última conexión
    if len(conns) >= 2:
        time_since_last = current_ts - conns[-1]
        
        # Intervalos entre conexiones
        intervals = []
        conn_list = list(conns)
        for i in range(1, len(conn_list)):
            intervals.append(conn_list[i] - conn_list[i-1])
        
        conn_interval = intervals[-1] if intervals else 0.0
        interval_stddev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        
        # Burst score: conexiones en último segundo / conexiones en último minuto
        conns_1s = len(get_connections_in_window(ip, current_ts, 1))
        burst_score = conns_1s / max(conn_60s, 1)
    else:
        time_since_last = 0.0
        conn_interval = 0.0
        interval_stddev = 0.0
        burst_score = 0.0
    
    return {
        "conn_interval": conn_interval,
        "time_since_last_conn": time_since_last,
        "conn_count_10s": conn_10s,
        "conn_count_60s": conn_60s,
        "conn_count_300s": conn_300s,
        "interval_stddev": interval_stddev,
        "burst_score": burst_score,
        "total_conn_from_ip": len(conns)
    }

def calculate_ja3_features(ja3: str, ip: str) -> Dict:
    """Calcula features relacionadas con JA3"""
    # Frecuencia del JA3
    ja3_freq = state.ja3_counts.get(ja3, 0)
    
    # Behavior score basado en frecuencia
    if ja3_freq == 0:
        ja3_behavior_score = 0.8  # Nuevo JA3, más sospechoso
    elif ja3_freq < 5:
        ja3_behavior_score = 0.6
    else:
        ja3_behavior_score = 0.4  # JA3 frecuente, menos sospechoso
    
    # JA3 únicos desde esta IP
    unique_ja3 = len(state.ja3_by_ip.get(ip, set()))
    
    return {
        "ja3_frequency": ja3_freq,
        "ja3_is_known": 0,  # Ya no usamos esta feature
        "ja3_behavior_score": ja3_behavior_score,
        "unique_ja3_from_ip": unique_ja3
    }

def calculate_ip_features(ip: str, current_ts: float) -> Dict:
    """
    Calcula features de IP.
    
    Nota: is_known_ip se deja siempre en 1 porque:
    - No usamos whitelist de IPs (sería convertir el problema en un simple if)
    - En AWS VPC todo el tráfico viene de microservicios conocidos
    - El modelo está entrenado con esta columna, así que la mantenemos
    """
    first_seen = state.ip_first_seen.get(ip, current_ts)
    hours_ago = (current_ts - first_seen) / 3600
    
    return {
        "is_known_ip": 1,  # Siempre 1 en producción
        "ip_first_seen_hours_ago": hours_ago
    }

def calculate_pattern_scores(ip: str, current_ts: float) -> Dict:
    """Calcula scores de patrones de ataque"""
    temporal = calculate_temporal_features(ip, current_ts)
    
    # Recon pattern: muchas conexiones rápidas
    recon_score = 0.2  # Base
    if temporal["conn_count_10s"] > 5:
        recon_score += 0.3
    if temporal["burst_score"] > 0.5:
        recon_score += 0.3
    
    # Recent activity score
    recent_score = min(temporal["conn_count_60s"] / 10, 1.0)
    
    return {
        "recon_pattern_score": min(recon_score, 1.0),
        "recent_activity_score": recent_score
    }

async def get_docker_features(ip: str, current_ts: float) -> Dict:
    """
    Obtiene features de Docker (versión simplificada para evitar flood de requests).
    Retorna defaults sin hacer HTTP requests por ahora.
    """
    return {
        "recent_docker_event": 0,
        "time_since_container_start": 0.0
    }

# ============================================
# PROCESAMIENTO PRINCIPAL
# ============================================

async def process_connection(conn: ZeekConnection, ssl: Optional[ZeekSSL]) -> DatasetRow:
    """Procesa una conexión y genera una fila del dataset"""
    try:
        ip = conn.orig_h
        ts = conn.ts
        
        if not isinstance(ts, (int, float)) or ts is None:
            logger.warning(f"Invalid ts for connection: {ts} (type: {type(ts)})")
            ts = time.time()
        
        # Actualizar estado
        if ip not in state.connections_by_ip:
            state.connections_by_ip[ip] = deque(maxlen=500)
        state.connections_by_ip[ip].append(ts)
        
        if ip not in state.ip_first_seen:
            state.ip_first_seen[ip] = ts
        
        state.all_durations.append(conn.duration)
        
        # JA3
        ja3 = ssl.ja3 if ssl else ""
        if ja3:
            state.ja3_counts[ja3] = state.ja3_counts.get(ja3, 0) + 1
            if ip not in state.ja3_by_ip:
                state.ja3_by_ip[ip] = set()
            state.ja3_by_ip[ip].add(ja3)
        
        # Calcular todas las features
        bytes_ratio = conn.orig_bytes / max(conn.resp_bytes, 1)
        duration_zscore = calculate_duration_zscore(conn.duration)
        temporal = calculate_temporal_features(ip, ts)
        ja3_features = calculate_ja3_features(ja3, ip)
        ip_features = calculate_ip_features(ip, ts)
        pattern_scores = calculate_pattern_scores(ip, ts)
        docker_features = await get_docker_features(ip, ts)
        
        row = DatasetRow(
            ts=ts,
            orig_h=ip,
            orig_p=conn.orig_p,
            resp_h=conn.resp_h,
            resp_p=conn.resp_p,
            orig_bytes=float(conn.orig_bytes),
            resp_bytes=float(conn.resp_bytes),
            bytes_ratio=bytes_ratio,
            duration=conn.duration,
            duration_zscore=duration_zscore,
            conn_state_encoded=encode_conn_state(conn.conn_state),
            conn_interval=temporal["conn_interval"],
            time_since_last_conn=temporal["time_since_last_conn"],
            conn_count_10s=temporal["conn_count_10s"],
            conn_count_60s=temporal["conn_count_60s"],
            conn_count_300s=temporal["conn_count_300s"],
            interval_stddev=temporal["interval_stddev"],
            burst_score=temporal["burst_score"],
            total_conn_from_ip=temporal["total_conn_from_ip"],
            hour_of_day=datetime.fromtimestamp(ts).hour,
            ja3=ja3,
            ja3_frequency=ja3_features["ja3_frequency"],
            ja3_is_known=ja3_features["ja3_is_known"],
            ja3_behavior_score=ja3_features["ja3_behavior_score"],
            unique_ja3_from_ip=ja3_features["unique_ja3_from_ip"],
            is_known_ip=ip_features["is_known_ip"],
            ip_first_seen_hours_ago=ip_features["ip_first_seen_hours_ago"],
            recon_pattern_score=pattern_scores["recon_pattern_score"],
            recent_activity_score=pattern_scores["recent_activity_score"],
            recent_docker_event=docker_features["recent_docker_event"],
            time_since_container_start=docker_features["time_since_container_start"]
        )
        
        return row
    except Exception as e:
        logger.error(f"Error processando conexión: {e}", exc_info=True)
        raise

def read_new_log_lines(log_path: Path) -> Tuple[List[str], List[str]]:
    """Lee nuevas líneas de un log de Zeek (soporta TSV y JSON)"""
    if not log_path.exists():
        return [], []
    
    path_str = str(log_path)
    last_pos = state.log_positions.get(path_str, 0)
    
    with open(log_path, 'r') as f:
        f.seek(last_pos)
        lines = f.readlines()
        state.log_positions[path_str] = f.tell()
    
    # Parsear header si es necesario
    headers = state.log_headers.get(path_str, [])
    data_lines = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Detectar si es JSON
        if line.startswith("{"):
            data_lines.append(line)
            # Para JSON no necesitamos headers
            if not headers:
                headers = ["json"]  # Marca que es JSON
        elif line.startswith("#fields"):
            headers = parse_zeek_header(line)
            state.log_headers[path_str] = headers
        elif not line.startswith("#"):
            data_lines.append(line)
    
    return data_lines, headers


def parse_conn_log_json(line: str) -> Optional[ZeekConnection]:
    """Parsea una línea JSON de conn.log"""
    try:
        data = json.loads(line)
        return ZeekConnection(
            ts=data.get("ts", 0.0) or 0.0,
            uid=data.get("uid", ""),
            orig_h=data.get("id.orig_h", ""),
            orig_p=data.get("id.orig_p", 0) or 0,
            resp_h=data.get("id.resp_h", ""),
            resp_p=data.get("id.resp_p", 0) or 0,
            proto=data.get("proto", "tcp"),
            duration=data.get("duration", 0.0) or 0.0,
            orig_bytes=data.get("orig_bytes", 0) or 0,
            resp_bytes=data.get("resp_bytes", 0) or 0,
            conn_state=data.get("conn_state", "SF"),
            orig_pkts=data.get("orig_pkts", 0) or 0,
            resp_pkts=data.get("resp_pkts", 0) or 0,
            missed_bytes=data.get("missed_bytes", 0) or 0
        )
    except Exception as e:
        logger.error(f"Error parseando conn.log JSON: {e}")
        return None


def parse_ssl_log_json(line: str) -> Optional[ZeekSSL]:
    """Parsea una línea JSON de ssl.log"""
    try:
        data = json.loads(line)
        return ZeekSSL(
            ts=data.get("ts", 0.0) or 0.0,
            uid=data.get("uid", ""),
            version=data.get("version", "TLSv12") or "TLSv12",
            cipher=data.get("cipher", "") or "",
            server_name=data.get("server_name", "") or "",
            ja3=data.get("ja3", "") or "",
            ja3s=data.get("ja3s", "") or "",
            resumed=data.get("resumed", False) or False,
            established=data.get("established", True)
        )
    except Exception as e:
        logger.error(f"Error parseando ssl.log JSON: {e}")
        return None

async def process_logs():
    """Procesa logs de Zeek y genera filas del dataset usando nuevo pipeline"""
    log_dir = Path(ZEEK_LOG_DIR)
    
    # Leer ssl.log primero para tener el mapping uid -> SSL
    ssl_path = log_dir / "ssl.log"
    ssl_lines, ssl_headers = read_new_log_lines(ssl_path)
    
    for line in ssl_lines:
        if ssl_headers:
            # Detectar formato JSON o TSV
            if ssl_headers == ["json"] or line.strip().startswith("{"):
                ssl = parse_ssl_log_json(line)
            else:
                ssl = parse_ssl_log_line(line, ssl_headers)
            if ssl and ssl.uid:
                # Añadir al pending del pipeline nuevo
                realtime_pipeline.dataset_generator.add_ssl(ssl)
    
    # Leer y procesar conn.log
    conn_path = log_dir / "conn.log"
    conn_lines, conn_headers = read_new_log_lines(conn_path)
    
    rows_generated = 0
    if conn_lines:
        logger.debug(f"Procesando {len(conn_lines)} líneas de conn.log")
    
    for line in conn_lines:
        if conn_headers:
            # Detectar formato JSON o TSV
            if conn_headers == ["json"] or line.strip().startswith("{"):
                conn = parse_conn_log_json(line)
            else:
                conn = parse_conn_log_line(line, conn_headers)
            
            if conn and conn.uid:
                # Convertir a formato nuevo
                new_conn = ZeekConnection(
                    ts=conn.ts,
                    uid=conn.uid,
                    orig_h=conn.orig_h,
                    orig_p=conn.orig_p,
                    resp_h=conn.resp_h,
                    resp_p=conn.resp_p,
                    proto=conn.proto,
                    duration=conn.duration,
                    orig_bytes=conn.orig_bytes,
                    resp_bytes=conn.resp_bytes,
                    conn_state=conn.conn_state,
                    orig_pkts=conn.orig_pkts,
                    resp_pkts=conn.resp_pkts,
                    missed_bytes=conn.missed_bytes
                )
                
                # NUEVO: Usar pipeline realtime
                # Devuelve (row, ventana_cerrada_si_cambio_ip)
                row, closed_window = realtime_pipeline.process_connection(new_conn)
                
                # Si se cerró una ventana por cambio de IP, enviarla inmediatamente
                if closed_window:
                    logger.info(f"🔄 Ventana cerrada por cambio IP: {closed_window.get('id.orig_h')} ({closed_window.get('n_connections')} conns)")
                    await send_window_to_ads(closed_window)
                
                # También mantener en buffer legacy por compatibilidad
                state.output_buffer.append(row)
                rows_generated += 1
                state.stats["rows_generated"] += 1
            else:
                if not conn:
                    logger.warning(f"parse_conn_log_line returned None for line")
                elif not conn.uid:
                    logger.warning(f"Connection has no UID: {conn}")
    
    state.stats["connections_processed"] += len(conn_lines)
    
    return rows_generated

# ============================================
# GENERACIÓN DE VENTANA DESLIZANTE (LEGACY - solo para compatibilidad)
# ============================================

# NOTA: El código nuevo usa realtime_pipeline que NO tiene solapamiento
# Este código se mantiene solo por compatibilidad con funciones legacy
WINDOW_CONFIG = WindowConfig(
    window_size_seconds=WINDOW_TIMEOUT_SECONDS,  # Usa el mismo timeout
    step_size_seconds=5.0,
    group_by_column='orig_h',
    timestamp_column='ts',
    label_column=None,
    numeric_columns=None,
    categorical_columns=None,
    numeric_aggregations=['mean', 'std', 'max', 'min']
)

window_analyzer = SlidingWindowAnalyzer(WINDOW_CONFIG)


def buffer_to_dataframe() -> pd.DataFrame:
    """Convierte el buffer actual a DataFrame para sliding window analysis"""
    if not state.output_buffer:
        return pd.DataFrame()
    
    # Convertir DatasetRow a dict
    rows_dict = [asdict(row) for row in state.output_buffer]
    return pd.DataFrame(rows_dict)


def generate_sliding_window(ip: str, current_ts: float, window_size_seconds: float = 30.0) -> Optional[Dict]:
    """
    Genera ventana deslizante para una IP específica.
    
    Esta función:
    1. Convierte el buffer a DataFrame
    2. Filtra por IP
    3. Aplica sliding window analysis usando el código de Gorka
    4. Retorna la ventana más reciente agregada
    
    El modelo espera una ventana de conexiones agregadas de la misma IP
    para detectar el patrón de ataque en 3 fases:
    - Fase 1 (recon): Muchas conexiones rápidas (burst_score alto)
    - Fase 2 (inject): Patrón de inyección
    - Fase 3 (check): Verificación
    
    Args:
        ip: IP origen de las conexiones
        current_ts: Timestamp actual (no usado actualmente)
        window_size_seconds: Tamaño de la ventana en segundos
    
    Returns:
        Diccionario con features agregados de la ventana, o None si no hay datos
    """
    try:
        # Convertir buffer a DataFrame
        df = buffer_to_dataframe()
        
        if df.empty:
            logger.debug(f"Buffer vacío para IP {ip}")
            return None
        
        # Filtrar por IP
        df_ip = df[df['orig_h'] == ip].copy()
        
        if df_ip.empty:
            logger.debug(f"No hay filas para IP {ip}")
            return None
            
        if len(df_ip) < 2:
            logger.debug(f"IP {ip} tiene {len(df_ip)} fila(s), necesita al menos 2")
            return None
        
        logger.debug(f"IP {ip}: buffer tiene {len(df_ip)} filas, aplicando sliding window...")
        
        # Aplicar sliding window analysis
        windowed_df = window_analyzer.transform(df_ip)
        
        if windowed_df.empty:
            logger.debug(f"Sliding window vació para IP {ip}")
            return None
        
        logger.debug(f"IP {ip}: sliding window generó {len(windowed_df)} ventanas")
        
        # Retornar la ventana más reciente
        latest_window = windowed_df.iloc[-1].to_dict()
        
        # Agregar metadata
        latest_window['ip'] = ip
        latest_window['window_rows'] = len(df_ip)
        
        logger.debug(f"Ventana generada para {ip}: {len(latest_window)} features")
        return latest_window
        
    except Exception as e:
        logger.error(f"Error generando sliding window para {ip}: {e}", exc_info=True)
        return None


async def process_windows_and_send():
    """
    ACTUALIZADO: Usa nuevo pipeline realtime para generar ventanas.
    
    Esta función:
    1. Obtiene ventanas del nuevo pipeline (correctamente calculadas)
    2. Envía cada ventana al ADS server para predicción
    """
    # Obtener todas las ventanas del pipeline realtime
    windows = realtime_pipeline.get_all_windows()
    
    if not windows:
        logger.debug("No hay ventanas listas para procesar")
        return
    
    logger.info(f"📊 Pipeline generó {len(windows)} ventanas para predicción")
    
    windows_sent = 0
    
    for window in windows:
        ip = window.get('id.orig_h', 'unknown')
        
        # Almacenar en historial para visualización
        window_entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "window_data": window,
            "n_connections": window.get('n_connections', 0),
            "burst_intensity": window.get('burst_intensity', 0),
            "heuristic_attack_score": window.get('heuristic_attack_score', 0)
        }
        RECENT_WINDOWS.append(window_entry)
        
        # Log detallado
        logger.info(f"📊 WINDOW - IP: {ip}, "
                   f"conns: {window.get('n_connections', 0)}, "
                   f"burst: {window.get('burst_intensity', 0):.3f}, "
                   f"attack_score: {window.get('heuristic_attack_score', 0):.3f}")
        
        # Enviar al ADS server
        await send_window_to_ads(window)
        windows_sent += 1
    
    if windows_sent > 0:
        logger.info(f"✅ Enviadas {windows_sent} ventanas al ADS server")


async def send_window_to_ads(window: Dict):
    """Envía una ventana agregada al servidor ADS para predicción"""
    if not window:
        return
    
    try:
        # Extraer IP de la ventana
        source_ip = window.get('id.orig_h') or window.get('ip') or 'unknown'
        
        payload = {
            "window": window,
            "timestamp": time.time(),
            "source_ip": source_ip
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                ADS_SERVER_URL,
                json=payload,
                timeout=10.0
            )
            
            if response.status_code == 200:
                state.stats["rows_sent"] += 1
                result = response.json()
                
                # Log si se detectó ataque
                if result.get('attack_detected'):
                    logger.warning(f"⚠️  ATAQUE DETECTADO desde IP {window.get('ip')}: {result.get('attack_score')}")
                    
            else:
                logger.error(f"Error enviando ventana al ADS: {response.status_code}")
                state.stats["errors"] += 1
                
    except Exception as e:
        logger.error(f"Error conectando a ADS server: {e}")
        state.stats["errors"] += 1


async def send_to_ads_server(rows: List[DatasetRow]):
    """Envía filas al servidor ADS para predicción"""
    if not rows:
        return
    
    try:
        payload = {
            "rows": [asdict(r) for r in rows]
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                ADS_SERVER_URL,
                json=payload,
                timeout=10.0
            )
            
            if response.status_code == 200:
                state.stats["rows_sent"] += len(rows)
                logger.info(f"Enviadas {len(rows)} filas al ADS server")
            else:
                logger.error(f"Error enviando al ADS: {response.status_code}")
                state.stats["errors"] += 1
                
    except Exception as e:
        logger.error(f"Error conectando a ADS server: {e}")
        state.stats["errors"] += 1

# ============================================
# BACKGROUND TASK
# ============================================

async def check_ip_change_and_process():
    """
    Verifica si cambió la IP y cierra la ventana anterior.
    Esto permite detectar patrones de ataque incluso con pocas conexiones.
    """
    if not state.output_buffer:
        return
    
    # Obtener la IP más reciente del buffer
    latest_row = state.output_buffer[-1]
    current_ip = latest_row.orig_h
    now = time.time()
    
    # Actualizar tiempo de última conexión
    state.last_connection_time = now
    
    # Si cambió la IP, procesar la ventana de la IP anterior
    # NOTA: Esto ya lo hace el realtime_pipeline automáticamente
    if state.last_seen_ip and current_ip != state.last_seen_ip:
        logger.info(f"🔄 Cambio de IP detectado: {state.last_seen_ip} → {current_ip}")
        
        # Procesar ventana de la IP anterior antes de que se mezcle
        state.pending_window_ip = state.last_seen_ip
        await process_windows_and_send()
        state.pending_window_ip = None
        # Resetear flag porque hay nueva IP
        state.window_sent_for_current_ip = False
    
    state.last_seen_ip = current_ip
    state.last_ip_change_time = now


async def check_window_timeout_and_process():
    """
    Verifica si pasaron 15 segundos desde la última conexión.
    Si es así, cierra la ventana y envía a predecir.
    """
    if not state.output_buffer:
        return False
    
    if state.last_connection_time == 0:
        return False
    
    # Ya se envió la ventana para esta IP, no reenviar
    if state.window_sent_for_current_ip:
        return False
    
    now = time.time()
    time_since_last = now - state.last_connection_time
    
    if time_since_last >= WINDOW_TIMEOUT_SECONDS:
        logger.info(f"⏱️ Timeout de ventana: {time_since_last:.1f}s >= {WINDOW_TIMEOUT_SECONDS}s")
        logger.info(f"   Cerrando ventana para IP: {state.last_seen_ip}")
        
        await process_windows_and_send()
        
        # Marcar que ya se envió para esta IP
        state.window_sent_for_current_ip = True
        return True
    
    return False


async def processing_loop():
    """Loop de procesamiento en background con ventanas SIN solapamiento
    
    Lógica de ventanas (nueva - sin solapamiento):
    - Cerrar ventana inmediatamente cuando llega conexión de otra IP
    - Cerrar ventana cuando pasan 15 segundos sin actividad de esa IP (timeout)
    """
    logger.info(f"Iniciando loop de procesamiento (intervalo: {PROCESS_INTERVAL}s)")
    logger.info(f"  Timeout ventanas: {realtime_pipeline.window_generator.config.timeout_seconds}s")
    logger.info(f"  Sin solapamiento - cierre por cambio de IP o timeout")
    
    loop_count = 0
    while True:
        try:
            loop_count += 1
            if loop_count % 20 == 0:  # Log every 20 iterations
                logger.info(f"[Loop {loop_count}] Procesando...")
            
            rows_generated = await process_logs()
            buffer_size = len(state.output_buffer)
            
            if rows_generated > 0:
                logger.info(f"Generadas {rows_generated} filas, buffer actual: {buffer_size}")
            
            # NUEVO: Verificar timeouts de ventanas (15 segundos sin actividad)
            timeout_windows = realtime_pipeline.check_timeouts()
            for window in timeout_windows:
                ip = window.get('id.orig_h', 'unknown')
                logger.info(f"⏰ Ventana cerrada por timeout: {ip} ({window.get('n_connections')} conns)")
                await send_window_to_ads(window)
                
                # Limpiar buffer legacy de esta IP
                old_size = len(state.output_buffer)
                items = [r for r in state.output_buffer if r.orig_h != ip]
                state.output_buffer = deque(items, maxlen=1000)
                if old_size > len(state.output_buffer):
                    logger.debug(f"🧹 Buffer limpiado: {old_size} → {len(state.output_buffer)} filas")
                
        except Exception as e:
            logger.error(f"Error en processing loop: {e}", exc_info=True)
            state.stats["errors"] += 1
        
        await asyncio.sleep(PROCESS_INTERVAL)

# ============================================
# ENDPOINTS
# ============================================

@app.on_event("startup")
async def startup():
    """Inicialización"""
    logger.info("Merger iniciado")
    logger.info(f"Zeek log dir: {ZEEK_LOG_DIR}")
    logger.info(f"Log Shipper URL: {LOG_SHIPPER_URL}")
    logger.info(f"ADS Server URL: {ADS_SERVER_URL}")
    
    # Iniciar loop de procesamiento en background
    asyncio.create_task(processing_loop())

@app.get("/health")
async def health():
    """Health check"""
    log_dir = Path(ZEEK_LOG_DIR)
    conn_exists = (log_dir / "conn.log").exists()
    ssl_exists = (log_dir / "ssl.log").exists()
    
    return {
        "status": "healthy",
        "zeek_logs_available": conn_exists and ssl_exists,
        "buffer_size": len(state.output_buffer),
        "connections_tracked": sum(len(v) for v in state.connections_by_ip.values())
    }

@app.get("/stats")
async def get_stats():
    """Estadísticas del Merger"""
    return {
        "stats": state.stats,
        "ips_tracked": len(state.connections_by_ip),
        "ja3_unique": len(state.ja3_counts),
        "pending_ssl": len(state.pending_ssl),
        "output_buffer": len(state.output_buffer),
        "pipeline_stats": realtime_pipeline.get_stats()
    }

@app.get("/pipeline/stats")
async def get_pipeline_stats():
    """Estadísticas detalladas del nuevo pipeline realtime"""
    return {
        "pipeline": realtime_pipeline.get_stats(),
        "last_windows": {ip: w.get('n_connections', 0) for ip, w in realtime_pipeline.last_windows.items()},
        "total_recent_windows": len(RECENT_WINDOWS)
    }

@app.get("/buffer")
async def get_buffer(limit: int = 50):
    """Obtiene filas del buffer (para debug)"""
    rows = list(state.output_buffer)[-limit:]
    return {
        "rows": [asdict(r) for r in rows],
        "count": len(rows)
    }

@app.get("/windows")
async def get_recent_windows(limit: int = 20):
    """
    Retorna las últimas windows generadas
    
    Útil para verificar que el pipeline genera correctamente las windows
    antes de enviarlas al modelo
    """
    all_windows = list(RECENT_WINDOWS)
    recent = all_windows[-limit:] if all_windows else []
    return {
        "total_windows_generated": len(RECENT_WINDOWS),
        "recent_windows": recent,
        "count": len(recent)
    }

@app.get("/windows/latest")
async def get_latest_window():
    """Retorna la última window generada"""
    if not RECENT_WINDOWS:
        raise HTTPException(status_code=404, detail="No windows generated yet")
    
    all_windows = list(RECENT_WINDOWS)
    latest = all_windows[-1] if all_windows else None
    if not latest:
        raise HTTPException(status_code=404, detail="No windows generated yet")
    return latest

@app.post("/process")
async def trigger_process():
    """Trigger manual del procesamiento"""
    rows = await process_logs()
    return {
        "status": "ok",
        "rows_generated": rows
    }


# ============================================
# DEREGISTER - Respuesta automática a ataques
# ============================================

@app.post("/deregister/{ip}")
async def deregister_services_by_ip(ip: str):
    """
    Desregistra todos los servicios de Consul que provienen de una IP específica.
    Este endpoint es llamado por el ADS Server cuando detecta un ataque.
    
    Args:
        ip: Dirección IP cuyos servicios deben ser desregistrados
        
    Returns:
        Lista de servicios desregistrados
    """
    logger.warning(f"🚨 DEREGISTER REQUEST: Desregistrando servicios de IP {ip}")
    
    deregistered_services = []
    errors = []
    
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            # 1. Obtener todos los servicios registrados
            response = await client.get(f"{CONSUL_BASE_URL}/catalog/services")
            if response.status_code != 200:
                raise HTTPException(
                    status_code=500, 
                    detail=f"Error al obtener servicios de Consul: {response.status_code}"
                )
            
            services = response.json()
            logger.info(f"Servicios encontrados en Consul: {list(services.keys())}")
            
            # 2. Para cada servicio, buscar instancias con la IP atacante
            for service_name in services.keys():
                if service_name == "consul":
                    continue  # No tocar el servicio de Consul
                
                # Obtener instancias del servicio
                svc_response = await client.get(
                    f"{CONSUL_BASE_URL}/catalog/service/{service_name}"
                )
                
                if svc_response.status_code != 200:
                    continue
                
                instances = svc_response.json()
                
                for instance in instances:
                    instance_ip = instance.get("ServiceAddress") or instance.get("Address")
                    service_id = instance.get("ServiceID")
                    
                    if instance_ip == ip and service_id:
                        # 3. Desregistrar este servicio
                        logger.warning(f"🗑️ Desregistrando servicio: {service_id} (IP: {ip})")
                        
                        dereg_response = await client.put(
                            f"{CONSUL_BASE_URL}/agent/service/deregister/{service_id}"
                        )
                        
                        if dereg_response.status_code == 200:
                            deregistered_services.append({
                                "service_id": service_id,
                                "service_name": service_name,
                                "ip": instance_ip
                            })
                            logger.info(f"✅ Servicio {service_id} desregistrado correctamente")
                        else:
                            errors.append({
                                "service_id": service_id,
                                "error": f"Status {dereg_response.status_code}"
                            })
                            logger.error(f"❌ Error desregistrando {service_id}: {dereg_response.status_code}")
    
    except httpx.RequestError as e:
        logger.error(f"❌ Error de conexión con Consul: {e}")
        raise HTTPException(status_code=503, detail=f"Error de conexión con Consul: {str(e)}")
    
    result = {
        "ip": ip,
        "deregistered_count": len(deregistered_services),
        "deregistered_services": deregistered_services,
        "errors": errors
    }
    
    if deregistered_services:
        logger.warning(f"🎯 RESULTADO: {len(deregistered_services)} servicios desregistrados de IP {ip}")
    else:
        logger.info(f"ℹ️ No se encontraron servicios de IP {ip} para desregistrar")
    
    return result


class ManualRow(BaseModel):
    """Para testing - insertar fila manual"""
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    orig_bytes: int
    resp_bytes: int
    duration: float
    ja3: Optional[str] = None

@app.post("/test/row")
async def test_row(row: ManualRow):
    """Endpoint de testing - procesa una fila manual"""
    conn = ZeekConnection(
        ts=datetime.now().timestamp(),
        uid="test-" + str(datetime.now().timestamp()),
        orig_h=row.orig_h,
        orig_p=row.orig_p,
        resp_h=row.resp_h,
        resp_p=row.resp_p,
        duration=row.duration,
        orig_bytes=row.orig_bytes,
        resp_bytes=row.resp_bytes
    )
    
    ssl = None
    if row.ja3:
        ssl = ZeekSSL(
            ts=conn.ts,
            uid=conn.uid,
            ja3=row.ja3
        )
    
    dataset_row = await process_connection(conn, ssl)
    
    return {
        "status": "ok",
        "row": asdict(dataset_row)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8082)
