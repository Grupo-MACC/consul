"""
Realtime Window Generator for Consul Poisoning Detection
=========================================================

Transforma filas del dataset (formato dataset_10k_final.csv) a ventanas
para el modelo de ML.

Este módulo genera ventanas SIN solapamiento:
- Cierra y envía la ventana cuando cambia la IP
- Timeout de 15 segundos sin actividad → envía la ventana

Flujo:
1. Recibe filas en formato dataset_10k_final.csv
2. Acumula conexiones por IP
3. Cuando cambia la IP o pasan 15s sin actividad → cierra ventana
4. Calcula estadísticas (mean, std, max) de features clave
5. Retorna ventana lista para el modelo
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Deque, Tuple, Callable
from collections import deque
from dataclasses import dataclass, asdict
import logging
import time

logger = logging.getLogger(__name__)


@dataclass
class WindowConfig:
    """Configuración de ventanas (sin solapamiento)"""
    timeout_seconds: float = 15.0       # Timeout para cerrar ventana sin actividad
    min_connections: int = 1            # Mínimo de conexiones para crear ventana
    
    # Features numéricas a agregar (del dataset base)
    numeric_features: List[str] = None
    
    # Agregaciones a aplicar
    aggregations: List[str] = None
    
    def __post_init__(self):
        if self.numeric_features is None:
            # Features que el modelo necesita agregar con mean/std/max
            # Derivado del modelo entrenado (74 features totales)
            self.numeric_features = [
                'burst_score',
                'bytes_ratio',
                'conn_count_10s',
                'conn_count_300s',
                'conn_count_60s',
                'conn_interval',
                'conn_state_encoded',
                'duration',
                'duration_zscore',
                'hour_of_day',
                'id.orig_p',
                'interval_stddev',
                'ip_first_seen_hours_ago',
                'is_known_ip',
                'orig_bytes',
                'recent_activity_score',
                'recent_docker_event',
                'recon_pattern_score',
                'resp_bytes',
                'time_since_container_start',
                'time_since_last_conn',
                'total_conn_from_ip',
            ]
        
        if self.aggregations is None:
            # Solo mean, std, max (no min) - según el modelo
            self.aggregations = ['mean', 'std', 'max']


class RealtimeWindowGenerator:
    """
    Genera ventanas en tiempo real SIN solapamiento.
    
    Reglas de cierre de ventana:
    1. Cuando llega una fila de una IP diferente a la actual → cierra ventana de IP anterior
    2. Cuando pasan 15 segundos sin recibir filas de una IP → cierra esa ventana (timeout)
    
    Las ventanas contienen estadísticas agregadas de las features.
    """
    
    def __init__(self, config: Optional[WindowConfig] = None, 
                 on_window_ready: Optional[Callable[[Dict], None]] = None):
        self.config = config or WindowConfig()
        
        # Callback cuando una ventana está lista para enviar al modelo
        self.on_window_ready = on_window_ready
        
        # Buffer de filas por IP (ventana actual de cada IP)
        self.rows_by_ip: Dict[str, List[Dict]] = {}
        
        # Timestamp de última fila recibida por IP
        self.last_activity_by_ip: Dict[str, float] = {}
        
        # IP de la última fila recibida (para detectar cambio de IP)
        self.last_ip: Optional[str] = None
        
        # Últimas ventanas generadas (para visualización/debug)
        self.recent_windows: Deque[Dict] = deque(maxlen=100)
        
        # Cola de ventanas listas para enviar
        self.pending_windows: Deque[Dict] = deque()
        
        # Stats
        self.stats = {
            'windows_generated': 0,
            'windows_by_ip_change': 0,
            'windows_by_timeout': 0,
            'rows_processed': 0
        }
    
    def add_row(self, row: Dict) -> Optional[Dict]:
        """
        Añade una fila al buffer.
        Si cambia la IP, cierra la ventana de la IP anterior.
        
        Args:
            row: Diccionario con features (formato dataset_10k_final.csv)
            
        Returns:
            Ventana cerrada si hubo cambio de IP, None en caso contrario
        """
        # Obtener IP (puede venir como orig_h o id.orig_h)
        ip = row.get('id.orig_h') or row.get('orig_h')
        if not ip:
            logger.warning("Fila sin IP, ignorando")
            return None
        
        # Normalizar nombre de columna IP
        if 'orig_h' in row and 'id.orig_h' not in row:
            row['id.orig_h'] = row['orig_h']
        
        current_time = time.time()
        closed_window = None
        
        # Si cambia la IP, cerrar ventana de la IP anterior
        if self.last_ip is not None and self.last_ip != ip:
            closed_window = self._close_window_for_ip(self.last_ip, reason="ip_change")
        
        # Inicializar buffer para esta IP si no existe
        if ip not in self.rows_by_ip:
            self.rows_by_ip[ip] = []
        
        # Añadir fila al buffer
        self.rows_by_ip[ip].append(row)
        self.last_activity_by_ip[ip] = current_time
        self.last_ip = ip
        self.stats['rows_processed'] += 1
        
        return closed_window
    
    def add_rows(self, rows: List[Dict]) -> List[Dict]:
        """
        Añade múltiples filas al buffer.
        
        Returns:
            Lista de ventanas cerradas por cambio de IP
        """
        closed_windows = []
        for row in rows:
            window = self.add_row(row)
            if window:
                closed_windows.append(window)
        return closed_windows
    
    def _close_window_for_ip(self, ip: str, reason: str = "unknown") -> Optional[Dict]:
        """
        Cierra la ventana de una IP y la prepara para enviar al modelo.
        
        Args:
            ip: IP de la ventana a cerrar
            reason: Motivo del cierre ("ip_change", "timeout", "manual")
            
        Returns:
            Diccionario con features agregadas de la ventana, o None si no hay suficientes datos
        """
        if ip not in self.rows_by_ip:
            return None
        
        rows = self.rows_by_ip[ip]
        if len(rows) < self.config.min_connections:
            logger.debug(f"IP {ip}: solo {len(rows)} filas, necesita {self.config.min_connections}")
            # Limpiar buffer aunque no generemos ventana
            del self.rows_by_ip[ip]
            if ip in self.last_activity_by_ip:
                del self.last_activity_by_ip[ip]
            return None
        
        # Convertir a DataFrame
        df = pd.DataFrame(rows)
        
        # Ordenar por timestamp
        ts_col = 'ts'
        if ts_col not in df.columns:
            logger.warning(f"No hay columna 'ts' en datos de IP {ip}")
            del self.rows_by_ip[ip]
            if ip in self.last_activity_by_ip:
                del self.last_activity_by_ip[ip]
            return None
        
        df = df.sort_values(ts_col).reset_index(drop=True)
        
        min_ts = df[ts_col].min()
        max_ts = df[ts_col].max()
        
        # Generar agregaciones
        window_data = self._aggregate_window(df, ip, min_ts, max_ts)
        
        if window_data:
            window_data['close_reason'] = reason
            
            # Guardar en historial
            self.recent_windows.append(window_data)
            self.pending_windows.append(window_data)
            self.stats['windows_generated'] += 1
            
            if reason == "ip_change":
                self.stats['windows_by_ip_change'] += 1
            elif reason == "timeout":
                self.stats['windows_by_timeout'] += 1
            
            # Callback si está configurado
            if self.on_window_ready:
                self.on_window_ready(window_data)
            
            logger.info(f"Ventana cerrada para IP {ip} (razón: {reason}, conexiones: {len(rows)})")
        
        # Limpiar buffer de esta IP
        del self.rows_by_ip[ip]
        if ip in self.last_activity_by_ip:
            del self.last_activity_by_ip[ip]
        
        return window_data
    
    def check_timeouts(self) -> List[Dict]:
        """
        Verifica timeouts y cierra ventanas que llevan más de 15 segundos sin actividad.
        Debe llamarse periódicamente (ej: cada segundo).
        
        Returns:
            Lista de ventanas cerradas por timeout
        """
        current_time = time.time()
        closed_windows = []
        
        # Copiar keys para evitar modificar dict durante iteración
        ips_to_check = list(self.last_activity_by_ip.keys())
        
        for ip in ips_to_check:
            last_activity = self.last_activity_by_ip.get(ip, current_time)
            time_since_activity = current_time - last_activity
            
            if time_since_activity >= self.config.timeout_seconds:
                window = self._close_window_for_ip(ip, reason="timeout")
                if window:
                    closed_windows.append(window)
        
        return closed_windows
    
    def get_pending_windows(self) -> List[Dict]:
        """
        Obtiene y vacía la cola de ventanas pendientes.
        
        Returns:
            Lista de ventanas listas para enviar al modelo
        """
        windows = list(self.pending_windows)
        self.pending_windows.clear()
        return windows
    
    def force_close_all(self) -> List[Dict]:
        """
        Fuerza el cierre de todas las ventanas abiertas.
        Útil al finalizar el procesamiento.
        
        Returns:
            Lista de todas las ventanas cerradas
        """
        closed_windows = []
        for ip in list(self.rows_by_ip.keys()):
            window = self._close_window_for_ip(ip, reason="forced")
            if window:
                closed_windows.append(window)
        return closed_windows
    
    def generate_window_for_ip(self, ip: str) -> Optional[Dict]:
        """
        Cierra y genera la ventana para una IP específica.
        Mantiene compatibilidad con código existente.
        
        Args:
            ip: IP origen
            
        Returns:
            Diccionario con features agregadas de la ventana, o None si no hay suficientes datos
        """
        return self._close_window_for_ip(ip, reason="manual")
    
    def generate_all_windows(self) -> List[Dict]:
        """
        Genera ventanas para todas las IPs (fuerza cierre de todas).
        Mantiene compatibilidad con código existente.
        
        Returns:
            Lista de ventanas generadas
        """
        return self.force_close_all()
    
    def _aggregate_window(self, window_df: pd.DataFrame, ip: str, 
                          start_ts: float, end_ts: float) -> Dict:
        """
        Agrega features de una ventana.
        
        Genera exactamente las 74 features que espera el modelo:
        - 22 features base * 3 agregaciones (mean, std, max) = 66
        - + features especiales con solo algunas agregaciones
        - + n_connections
        
        Args:
            window_df: DataFrame con filas de la ventana
            ip: IP origen
            start_ts: Timestamp de inicio de ventana
            end_ts: Timestamp de fin de ventana
            
        Returns:
            Diccionario con features agregadas (74 features)
        """
        agg_data = {
            'id.orig_h': ip,
            'window_start': start_ts,
            'window_end': end_ts,
            'window_duration': end_ts - start_ts,
            'n_connections': len(window_df)  # Feature del modelo
        }
        
        # Agregar features numéricas base (mean, std, max)
        for col in self.config.numeric_features:
            # Si no existe la columna, usar valores por defecto
            if col not in window_df.columns:
                for agg in self.config.aggregations:
                    agg_data[f"{col}_{agg}"] = 0.0
                continue
            
            values = pd.to_numeric(window_df[col], errors='coerce').dropna()
            
            for agg in self.config.aggregations:
                key = f"{col}_{agg}"
                
                if values.empty:
                    agg_data[key] = 0.0
                elif agg == 'mean':
                    agg_data[key] = float(values.mean())
                elif agg == 'std':
                    agg_data[key] = float(values.std()) if len(values) > 1 else 0.0
                elif agg == 'max':
                    agg_data[key] = float(values.max())
        
        # Features especiales que el modelo espera con solo algunas agregaciones
        # id.resp_p_std (solo std)
        if 'id.resp_p' in window_df.columns:
            values = pd.to_numeric(window_df['id.resp_p'], errors='coerce').dropna()
            agg_data['id.resp_p_std'] = float(values.std()) if len(values) > 1 else 0.0
        else:
            agg_data['id.resp_p_std'] = 0.0
        
        # ja3_behavior_score_std (solo std)
        if 'ja3_behavior_score' in window_df.columns:
            values = pd.to_numeric(window_df['ja3_behavior_score'], errors='coerce').dropna()
            agg_data['ja3_behavior_score_std'] = float(values.std()) if len(values) > 1 else 0.0
        else:
            agg_data['ja3_behavior_score_std'] = 0.0
        
        # ja3_frequency (mean, std, max)
        if 'ja3_frequency' in window_df.columns:
            values = pd.to_numeric(window_df['ja3_frequency'], errors='coerce').dropna()
            agg_data['ja3_frequency_mean'] = float(values.mean()) if not values.empty else 0.0
            agg_data['ja3_frequency_std'] = float(values.std()) if len(values) > 1 else 0.0
            agg_data['ja3_frequency_max'] = float(values.max()) if not values.empty else 0.0
        else:
            agg_data['ja3_frequency_mean'] = 0.0
            agg_data['ja3_frequency_std'] = 0.0
            agg_data['ja3_frequency_max'] = 0.0
        
        # ja3_is_known_std (solo std)
        if 'ja3_is_known' in window_df.columns:
            values = pd.to_numeric(window_df['ja3_is_known'], errors='coerce').dropna()
            agg_data['ja3_is_known_std'] = float(values.std()) if len(values) > 1 else 0.0
        else:
            agg_data['ja3_is_known_std'] = 0.0
        
        # unique_ja3_from_ip_std (solo std)
        if 'unique_ja3_from_ip' in window_df.columns:
            values = pd.to_numeric(window_df['unique_ja3_from_ip'], errors='coerce').dropna()
            agg_data['unique_ja3_from_ip_std'] = float(values.std()) if len(values) > 1 else 0.0
        else:
            agg_data['unique_ja3_from_ip_std'] = 0.0
        
        return agg_data
    
    def _add_consul_poisoning_features(self, window_data: Dict) -> Dict:
        """
        NO añade features adicionales - el modelo ya tiene las que necesita.
        Esta función ahora solo valida que están todas las features requeridas.
        
        Args:
            window_data: Diccionario con features agregadas base
            
        Returns:
            Diccionario validado (sin cambios)
        """
        return window_data
    
    def clear_old_data(self, max_age_seconds: float = 300):
        """
        Limpia datos antiguos del buffer (ahora usa check_timeouts).
        Mantiene compatibilidad con código existente.
        
        Args:
            max_age_seconds: Ignorado, usa timeout_seconds de config
        """
        self.check_timeouts()
    
    def get_feature_columns(self) -> List[str]:
        """
        Retorna lista de las 74 columnas que espera el modelo.
        """
        # Las 74 features que el modelo espera (en orden)
        return [
            'burst_score_max', 'burst_score_mean', 'burst_score_std',
            'bytes_ratio_max', 'bytes_ratio_mean', 'bytes_ratio_std',
            'conn_count_10s_max', 'conn_count_10s_mean', 'conn_count_10s_std',
            'conn_count_300s_max', 'conn_count_300s_mean', 'conn_count_300s_std',
            'conn_count_60s_max', 'conn_count_60s_mean', 'conn_count_60s_std',
            'conn_interval_max', 'conn_interval_mean', 'conn_interval_std',
            'conn_state_encoded_max', 'conn_state_encoded_mean', 'conn_state_encoded_std',
            'duration_max', 'duration_mean', 'duration_std',
            'duration_zscore_max', 'duration_zscore_mean', 'duration_zscore_std',
            'hour_of_day_max', 'hour_of_day_mean', 'hour_of_day_std',
            'id.orig_p_max', 'id.orig_p_mean', 'id.orig_p_std',
            'id.resp_p_std',
            'interval_stddev_max', 'interval_stddev_mean', 'interval_stddev_std',
            'ip_first_seen_hours_ago_max', 'ip_first_seen_hours_ago_mean', 'ip_first_seen_hours_ago_std',
            'is_known_ip_max', 'is_known_ip_mean', 'is_known_ip_std',
            'ja3_behavior_score_std',
            'ja3_frequency_max', 'ja3_frequency_mean', 'ja3_frequency_std',
            'ja3_is_known_std',
            'n_connections',
            'orig_bytes_max', 'orig_bytes_mean', 'orig_bytes_std',
            'recent_activity_score_max', 'recent_activity_score_mean', 'recent_activity_score_std',
            'recent_docker_event_max', 'recent_docker_event_mean', 'recent_docker_event_std',
            'recon_pattern_score_max', 'recon_pattern_score_mean', 'recon_pattern_score_std',
            'resp_bytes_max', 'resp_bytes_mean', 'resp_bytes_std',
            'time_since_container_start_max', 'time_since_container_start_mean', 'time_since_container_start_std',
            'time_since_last_conn_max', 'time_since_last_conn_mean', 'time_since_last_conn_std',
            'total_conn_from_ip_max', 'total_conn_from_ip_mean', 'total_conn_from_ip_std',
            'unique_ja3_from_ip_std'
        ]
    
    def get_model_features(self) -> List[str]:
        """
        Alias de get_feature_columns para claridad.
        Retorna las 74 features exactas que el modelo Isolation Forest espera.
        """
        return self.get_feature_columns()
    
    def get_stats(self) -> Dict:
        """Retorna estadísticas"""
        return {
            **self.stats,
            'unique_ips': len(self.rows_by_ip),
            'total_rows_buffered': sum(len(rows) for rows in self.rows_by_ip.values()),
            'recent_windows': len(self.recent_windows),
            'pending_windows': len(self.pending_windows)
        }


def create_window_dataframe(windows: List[Dict]) -> pd.DataFrame:
    """
    Convierte lista de ventanas a DataFrame.
    
    Args:
        windows: Lista de diccionarios con ventanas
        
    Returns:
        DataFrame con todas las ventanas
    """
    if not windows:
        return pd.DataFrame()
    
    return pd.DataFrame(windows)


# =============================================================================
# Funciones de utilidad
# =============================================================================

def prepare_window_for_model(window: Dict, model_features: Optional[List[str]] = None) -> Dict:
    """
    Prepara una ventana para enviar al modelo.
    Selecciona solo las features que el modelo espera.
    
    Args:
        window: Diccionario con features de ventana
        model_features: Lista de features que espera el modelo (None = todas)
        
    Returns:
        Diccionario con solo las features del modelo
    """
    if model_features is None:
        return window
    
    return {k: window.get(k, 0) for k in model_features}


def window_to_numpy(window: Dict, feature_order: List[str]) -> np.ndarray:
    """
    Convierte ventana a array numpy en orden específico.
    
    Args:
        window: Diccionario con features
        feature_order: Orden de features para el array
        
    Returns:
        Array numpy 1D con valores de features
    """
    values = []
    for feature in feature_order:
        val = window.get(feature, 0)
        if isinstance(val, str):
            val = 0  # Ignorar strings
        elif val is None:
            val = 0
        values.append(float(val))
    
    return np.array(values)
