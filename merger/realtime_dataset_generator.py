"""
Realtime Dataset Generator for Consul Poisoning Detection
=========================================================

Este módulo genera filas en formato idéntico al dataset_10k_final.csv
a partir de logs de Zeek y eventos de Docker en tiempo real.

Flujo:
1. Recibe conexiones de Zeek (conn.log + ssl.log)
2. Recibe eventos de Docker (reinicios de contenedores)
3. Calcula todas las features comportamentales
4. Genera filas listas para el modelo o para sliding window

Columnas generadas (igual que dataset_10k_final.csv):
- Identificadores: ts, id.orig_h, id.orig_p, id.resp_h, id.resp_p
- Conexión: orig_bytes, resp_bytes, bytes_ratio, duration, duration_zscore, conn_state_encoded
- Temporales: conn_interval, time_since_last_conn, conn_count_10s, conn_count_60s, 
              conn_count_300s, interval_stddev, burst_score, total_conn_from_ip, hour_of_day
- JA3: ja3, ja3_frequency, ja3_is_known, ja3_behavior_score, unique_ja3_from_ip
- IP: is_known_ip, ip_first_seen_hours_ago
- Patrones: recon_pattern_score, recent_activity_score
- Docker: recent_docker_event, time_since_container_start
"""

import time
import logging
import statistics
from datetime import datetime
from collections import deque
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Deque, Set
import numpy as np

logger = logging.getLogger(__name__)

# Ventanas temporales (igual que en generate_dataset.py original)
WINDOW_10S = 10
WINDOW_60S = 60  
WINDOW_300S = 300

# JA3 conocido de microservicios Python legítimos
KNOWN_JA3 = "304734bb1c086c3453b387400cf83f11"

# Ventana para correlacionar eventos de Docker
DOCKER_EVENT_WINDOW = 60  # segundos


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


@dataclass
class ZeekSSL:
    """Datos SSL parseados de ssl.log"""
    ts: float
    uid: str
    ja3: str = ""
    ja3s: str = ""


@dataclass
class DockerEvent:
    """Evento de Docker (reinicio de contenedor)"""
    timestamp: float
    event_type: str  # 'restart', 'start'
    service: str
    service_ip: str = ""


@dataclass
class DatasetRow:
    """
    Fila del dataset con todas las features calculadas.
    Formato idéntico a dataset_10k_final.csv
    """
    # Identificadores
    ts: float
    orig_h: str  # Nota: usamos orig_h para compatibilidad interna, se mapea a id.orig_h en export
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
    
    def to_dict_with_zeek_columns(self) -> Dict:
        """
        Convierte a diccionario con nombres de columna compatibles con dataset original.
        Mapea orig_h -> id.orig_h, etc.
        """
        d = asdict(self)
        # Renombrar columnas para coincidir con formato Zeek/dataset original
        d['id.orig_h'] = d.pop('orig_h')
        d['id.orig_p'] = d.pop('orig_p')
        d['id.resp_h'] = d.pop('resp_h')
        d['id.resp_p'] = d.pop('resp_p')
        return d


class RealtimeDatasetGenerator:
    """
    Generador de dataset en tiempo real.
    
    Mantiene estado de conexiones por IP para calcular features temporales.
    Genera filas idénticas al formato dataset_10k_final.csv.
    """
    
    def __init__(self, max_history: int = 1000):
        """
        Args:
            max_history: Máximo de conexiones a mantener en historial por IP
        """
        # Historial de conexiones por IP (para calcular features temporales)
        self.connections_by_ip: Dict[str, Deque[float]] = {}
        
        # Historial de todas las duraciones (para z-score)
        self.all_durations: Deque[float] = deque(maxlen=max_history)
        
        # Conteo de JA3 (para frecuencia)
        self.ja3_counts: Dict[str, int] = {}
        
        # JA3 por IP (para unique_ja3_from_ip)
        self.ja3_by_ip: Dict[str, Set[str]] = {}
        
        # Primera vez vista cada IP (para ip_first_seen_hours_ago)
        self.ip_first_seen: Dict[str, float] = {}
        
        # Eventos de Docker recientes (para correlacionar con conexiones)
        self.docker_events: Deque[DockerEvent] = deque(maxlen=500)
        
        # Mapeo servicio -> IP (para correlacionar Docker events)
        self.service_to_ip: Dict[str, str] = {}
        
        # SSL pendiente por uid
        self.pending_ssl: Dict[str, ZeekSSL] = {}
        
        # Buffer de filas generadas
        self.rows_buffer: Deque[DatasetRow] = deque(maxlen=max_history)
        
        # Configuración
        self.max_history = max_history
        
        # Stats
        self.stats = {
            'connections_processed': 0,
            'rows_generated': 0,
            'docker_events_received': 0
        }
    
    # =========================================================================
    # Registro de eventos
    # =========================================================================
    
    def register_ssl(self, ssl: ZeekSSL):
        """Registra info SSL para asociar con conexiones por uid"""
        if ssl.uid:
            self.pending_ssl[ssl.uid] = ssl
    
    def add_ssl(self, ssl: ZeekSSL):
        """Alias de register_ssl para compatibilidad"""
        self.register_ssl(ssl)
    
    def register_docker_event(self, event: DockerEvent):
        """Registra evento de Docker (reinicio)"""
        self.docker_events.append(event)
        if event.service_ip:
            self.service_to_ip[event.service] = event.service_ip
        self.stats['docker_events_received'] += 1
        logger.debug(f"Docker event registrado: {event.service} @ {event.timestamp}")
    
    def register_service_ip(self, service: str, ip: str):
        """Registra mapeo servicio -> IP"""
        self.service_to_ip[service] = ip
    
    # =========================================================================
    # Codificación y cálculos básicos
    # =========================================================================
    
    @staticmethod
    def encode_conn_state(conn_state: str) -> int:
        """Codifica estado de conexión (igual que dataset original)"""
        states = {
            'SF': 0, 'S0': 1, 'REJ': 2, 'RSTO': 3, 'RSTR': 3, 'OTH': 2,
            'S1': 1, 'S2': 4, 'S3': 5, 'RSTOS0': 8, 'RSTRH': 9, 'SH': 10, 'SHR': 11
        }
        return states.get(conn_state, 2)
    
    def calculate_duration_zscore(self, duration: float) -> float:
        """Calcula z-score de duración basado en historial"""
        if len(self.all_durations) < 2:
            return 0.0
        
        try:
            mean = statistics.mean(self.all_durations)
            stdev = statistics.stdev(self.all_durations)
            if stdev == 0:
                return 0.0
            return (duration - mean) / stdev
        except:
            return 0.0
    
    # =========================================================================
    # Features temporales
    # =========================================================================
    
    def get_connections_in_window(self, ip: str, current_ts: float, window_seconds: float) -> int:
        """Cuenta conexiones en ventana temporal"""
        if ip not in self.connections_by_ip:
            return 0
        
        cutoff = current_ts - window_seconds
        return sum(1 for ts in self.connections_by_ip[ip] if ts >= cutoff)
    
    def calculate_temporal_features(self, ip: str, current_ts: float) -> Dict:
        """
        Calcula features temporales para una IP.
        Igual que generate_dataset.py original.
        """
        conns = self.connections_by_ip.get(ip, deque())
        conn_list = list(conns)
        
        # Conexiones en diferentes ventanas
        conn_10s = self.get_connections_in_window(ip, current_ts, WINDOW_10S)
        conn_60s = self.get_connections_in_window(ip, current_ts, WINDOW_60S)
        conn_300s = self.get_connections_in_window(ip, current_ts, WINDOW_300S)
        
        # Total conexiones de esta IP
        total_conn = len(conn_list) + 1  # +1 por la conexión actual
        
        # Intervalos
        time_since_last = None
        conn_interval = 0.0
        interval_stddev = 0.0
        burst_score = 0.0
        
        if len(conn_list) >= 1:
            time_since_last = current_ts - conn_list[-1]
            conn_interval = time_since_last
            
            # Calcular stddev de intervalos
            if len(conn_list) >= 2:
                intervals = []
                for i in range(1, len(conn_list)):
                    intervals.append(conn_list[i] - conn_list[i-1])
                intervals.append(time_since_last)
                
                if len(intervals) > 1:
                    interval_stddev = float(np.std(intervals))
            
            # Burst score: conexiones en último segundo / conexiones en último minuto
            conn_1s = self.get_connections_in_window(ip, current_ts, 1)
            if conn_60s > 0:
                burst_score = conn_1s / conn_60s
            else:
                burst_score = 0.0
        
        return {
            'conn_interval': conn_interval,
            'time_since_last_conn': time_since_last,
            'conn_count_10s': conn_10s + 1,  # +1 por conexión actual
            'conn_count_60s': conn_60s + 1,
            'conn_count_300s': conn_300s + 1,
            'interval_stddev': interval_stddev,
            'burst_score': burst_score,
            'total_conn_from_ip': total_conn
        }
    
    # =========================================================================
    # Features JA3
    # =========================================================================
    
    def calculate_ja3_features(self, ja3: str, ip: str) -> Dict:
        """Calcula features JA3"""
        # Frecuencia del JA3
        ja3_freq = self.ja3_counts.get(ja3, 0)
        
        # Es conocido (microservicio Python legítimo)
        ja3_is_known = 1 if ja3 == KNOWN_JA3 else 0
        
        # Behavior score
        ja3_behavior_score = 0.5  # Base
        if ja3 == KNOWN_JA3:
            ja3_behavior_score = 0.5
        elif ja3_freq == 0:
            ja3_behavior_score = 0.8  # Nuevo JA3, más sospechoso
        
        # JA3 únicos desde esta IP
        unique_ja3 = len(self.ja3_by_ip.get(ip, set()))
        if ja3 and ja3 not in self.ja3_by_ip.get(ip, set()):
            unique_ja3 += 1
        
        return {
            'ja3_frequency': ja3_freq,
            'ja3_is_known': ja3_is_known,
            'ja3_behavior_score': ja3_behavior_score,
            'unique_ja3_from_ip': max(unique_ja3, 1)
        }
    
    # =========================================================================
    # Features de IP
    # =========================================================================
    
    def calculate_ip_features(self, ip: str, current_ts: float) -> Dict:
        """Calcula features de IP"""
        first_seen = self.ip_first_seen.get(ip, current_ts)
        hours_ago = (current_ts - first_seen) / 3600
        
        return {
            'is_known_ip': 1,  # En producción siempre 1 (no usamos whitelist)
            'ip_first_seen_hours_ago': hours_ago
        }
    
    # =========================================================================
    # Features de patrones
    # =========================================================================
    
    def calculate_pattern_features(self, temporal: Dict) -> Dict:
        """Calcula scores de patrones de comportamiento"""
        # Recon pattern score (SOLO comportamental)
        recon_score = (
            0.5 * (1 if temporal['burst_score'] > 0.3 else 0) +
            0.3 * (1 if temporal['conn_count_10s'] > 2 else 0) +
            0.2 * (1 if temporal['conn_interval'] < 60 else 0)
        )
        
        # Recent activity score
        # Normalizado: asumimos max razonable de 10 conexiones en 10s
        recent_score = min(temporal['conn_count_10s'] / 10, 1.0)
        
        return {
            'recon_pattern_score': min(recon_score, 1.0),
            'recent_activity_score': recent_score
        }
    
    # =========================================================================
    # Features Docker
    # =========================================================================
    
    def calculate_docker_features(self, ip: str, current_ts: float) -> Dict:
        """
        Calcula features de Docker.
        Busca si hay un evento de reinicio reciente para esta IP.
        """
        recent_event = 0
        time_since_start = 0.0
        
        # Buscar eventos de Docker para esta IP
        for event in reversed(list(self.docker_events)):
            event_ip = event.service_ip or self.service_to_ip.get(event.service, '')
            
            if event_ip == ip:
                time_diff = current_ts - event.timestamp
                
                # Conexión ocurrió después del reinicio, dentro de la ventana
                if 0 <= time_diff <= DOCKER_EVENT_WINDOW:
                    recent_event = 1
                    time_since_start = time_diff
                    break
        
        return {
            'recent_docker_event': recent_event,
            'time_since_container_start': time_since_start
        }
    
    # =========================================================================
    # Procesamiento principal
    # =========================================================================
    
    def process_connection(self, conn: ZeekConnection, ssl: Optional[ZeekSSL] = None) -> DatasetRow:
        """
        Procesa una conexión y genera una fila del dataset.
        
        Args:
            conn: Conexión de Zeek
            ssl: Datos SSL opcionales (si no se pasan, busca por uid en pending_ssl)
            
        Returns:
            DatasetRow con todas las features calculadas
        """
        ip = conn.orig_h
        ts = conn.ts
        
        # Buscar SSL: primero argumento, luego por uid en pending
        if ssl is None:
            ssl = self.pending_ssl.pop(conn.uid, None)
        ja3 = ssl.ja3 if ssl and ssl.ja3 else KNOWN_JA3
        
        # Actualizar estado ANTES de calcular features
        # (así la conexión actual no se cuenta en el historial)
        
        # Calcular todas las features
        bytes_ratio = conn.orig_bytes / max(conn.orig_bytes + conn.resp_bytes, 1)
        duration_zscore = self.calculate_duration_zscore(conn.duration)
        temporal = self.calculate_temporal_features(ip, ts)
        ja3_features = self.calculate_ja3_features(ja3, ip)
        ip_features = self.calculate_ip_features(ip, ts)
        pattern_features = self.calculate_pattern_features(temporal)
        docker_features = self.calculate_docker_features(ip, ts)
        
        # Crear fila
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
            conn_state_encoded=self.encode_conn_state(conn.conn_state),
            conn_interval=temporal['conn_interval'],
            time_since_last_conn=temporal['time_since_last_conn'],
            conn_count_10s=temporal['conn_count_10s'],
            conn_count_60s=temporal['conn_count_60s'],
            conn_count_300s=temporal['conn_count_300s'],
            interval_stddev=temporal['interval_stddev'],
            burst_score=temporal['burst_score'],
            total_conn_from_ip=temporal['total_conn_from_ip'],
            hour_of_day=datetime.fromtimestamp(ts).hour,
            ja3=ja3,
            ja3_frequency=ja3_features['ja3_frequency'],
            ja3_is_known=ja3_features['ja3_is_known'],
            ja3_behavior_score=ja3_features['ja3_behavior_score'],
            unique_ja3_from_ip=ja3_features['unique_ja3_from_ip'],
            is_known_ip=ip_features['is_known_ip'],
            ip_first_seen_hours_ago=ip_features['ip_first_seen_hours_ago'],
            recon_pattern_score=pattern_features['recon_pattern_score'],
            recent_activity_score=pattern_features['recent_activity_score'],
            recent_docker_event=docker_features['recent_docker_event'],
            time_since_container_start=docker_features['time_since_container_start']
        )
        
        # Actualizar estado DESPUÉS de crear la fila
        self._update_state(ip, ts, conn.duration, ja3)
        
        # Guardar en buffer
        self.rows_buffer.append(row)
        self.stats['connections_processed'] += 1
        self.stats['rows_generated'] += 1
        
        return row
    
    def _update_state(self, ip: str, ts: float, duration: float, ja3: str):
        """Actualiza estado interno después de procesar conexión"""
        # Historial de conexiones por IP
        if ip not in self.connections_by_ip:
            self.connections_by_ip[ip] = deque(maxlen=self.max_history)
        self.connections_by_ip[ip].append(ts)
        
        # Primera vez vista
        if ip not in self.ip_first_seen:
            self.ip_first_seen[ip] = ts
        
        # Duración para z-score
        self.all_durations.append(duration)
        
        # JA3
        if ja3:
            self.ja3_counts[ja3] = self.ja3_counts.get(ja3, 0) + 1
            if ip not in self.ja3_by_ip:
                self.ja3_by_ip[ip] = set()
            self.ja3_by_ip[ip].add(ja3)
    
    def get_rows_as_dicts(self, with_zeek_columns: bool = True) -> List[Dict]:
        """
        Retorna filas del buffer como lista de diccionarios.
        
        Args:
            with_zeek_columns: Si True, usa nombres de columna tipo Zeek (id.orig_h)
            
        Returns:
            Lista de diccionarios con las filas
        """
        if with_zeek_columns:
            return [row.to_dict_with_zeek_columns() for row in self.rows_buffer]
        return [asdict(row) for row in self.rows_buffer]
    
    def clear_buffer(self):
        """Limpia el buffer de filas"""
        self.rows_buffer.clear()
    
    def get_stats(self) -> Dict:
        """Retorna estadísticas"""
        return {
            **self.stats,
            'buffer_size': len(self.rows_buffer),
            'unique_ips_tracked': len(self.connections_by_ip),
            'ja3_variants': len(self.ja3_counts)
        }
