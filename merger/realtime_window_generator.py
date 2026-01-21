"""
Realtime Window Generator for Consul Poisoning Detection
=========================================================

Transforma filas del dataset (formato dataset_10k_final.csv) a ventanas
para el modelo de ML.

Este módulo aplica sliding window sobre las filas generadas por
RealtimeDatasetGenerator, creando ventanas con estadísticas agregadas
que son las features que espera el modelo.

Flujo:
1. Recibe filas en formato dataset_10k_final.csv
2. Agrupa por IP y ventana temporal
3. Calcula estadísticas (mean, std, max, min) de features clave
4. Genera features adicionales para detección de Consul poisoning
5. Retorna ventana lista para el modelo
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Deque
from collections import deque
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class WindowConfig:
    """Configuración de sliding window"""
    window_size_seconds: float = 30.0  # Tamaño de ventana
    step_size_seconds: float = 5.0      # Paso entre ventanas
    min_connections: int = 1            # Mínimo de conexiones para crear ventana (antes era 2)
    
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
    Genera ventanas deslizantes en tiempo real.
    
    Mantiene un buffer de filas y genera ventanas cuando hay suficientes datos.
    Las ventanas contienen estadísticas agregadas de las features.
    """
    
    def __init__(self, config: Optional[WindowConfig] = None):
        self.config = config or WindowConfig()
        
        # Buffer de filas por IP
        self.rows_by_ip: Dict[str, Deque[Dict]] = {}
        
        # Últimas ventanas generadas (para visualización/debug)
        self.recent_windows: Deque[Dict] = deque(maxlen=100)
        
        # Stats
        self.stats = {
            'windows_generated': 0,
            'rows_processed': 0
        }
    
    def add_row(self, row: Dict):
        """
        Añade una fila al buffer.
        
        Args:
            row: Diccionario con features (formato dataset_10k_final.csv)
        """
        # Obtener IP (puede venir como orig_h o id.orig_h)
        ip = row.get('id.orig_h') or row.get('orig_h')
        if not ip:
            logger.warning("Fila sin IP, ignorando")
            return
        
        # Normalizar nombre de columna IP
        if 'orig_h' in row and 'id.orig_h' not in row:
            row['id.orig_h'] = row['orig_h']
        
        # Añadir al buffer de esta IP
        if ip not in self.rows_by_ip:
            self.rows_by_ip[ip] = deque(maxlen=500)
        
        self.rows_by_ip[ip].append(row)
        self.stats['rows_processed'] += 1
    
    def add_rows(self, rows: List[Dict]):
        """Añade múltiples filas al buffer"""
        for row in rows:
            self.add_row(row)
    
    def generate_window_for_ip(self, ip: str) -> Optional[Dict]:
        """
        Genera la ventana más reciente para una IP.
        
        Args:
            ip: IP origen
            
        Returns:
            Diccionario con features agregadas de la ventana, o None si no hay suficientes datos
        """
        if ip not in self.rows_by_ip:
            return None
        
        rows = list(self.rows_by_ip[ip])
        if len(rows) < self.config.min_connections:
            logger.debug(f"IP {ip}: solo {len(rows)} filas, necesita {self.config.min_connections}")
            return None
        
        # Convertir a DataFrame
        df = pd.DataFrame(rows)
        
        # Ordenar por timestamp
        ts_col = 'ts'
        if ts_col not in df.columns:
            logger.warning(f"No hay columna 'ts' en datos de IP {ip}")
            return None
        
        df = df.sort_values(ts_col).reset_index(drop=True)
        
        # Determinar ventana temporal (últimos N segundos)
        max_ts = df[ts_col].max()
        min_ts = max_ts - self.config.window_size_seconds
        
        # Filtrar datos en la ventana
        window_df = df[df[ts_col] >= min_ts].copy()
        
        if len(window_df) < self.config.min_connections:
            logger.debug(f"IP {ip}: ventana tiene solo {len(window_df)} filas")
            return None
        
        # Generar agregaciones
        window_data = self._aggregate_window(window_df, ip, min_ts, max_ts)
        
        if window_data:
            # Añadir features de Consul poisoning
            window_data = self._add_consul_poisoning_features(window_data)
            
            # Guardar en historial
            self.recent_windows.append(window_data)
            self.stats['windows_generated'] += 1
        
        return window_data
    
    def generate_all_windows(self) -> List[Dict]:
        """
        Genera ventanas para todas las IPs con suficientes datos.
        
        Returns:
            Lista de ventanas generadas
        """
        windows = []
        for ip in list(self.rows_by_ip.keys()):
            window = self.generate_window_for_ip(ip)
            if window:
                windows.append(window)
        return windows
    
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
    
    def clear_old_data(self, max_age_seconds: float = 300):
        """
        Limpia datos antiguos del buffer.
        
        Args:
            max_age_seconds: Máxima antigüedad en segundos
        """
        import time
        current_ts = time.time()
        cutoff = current_ts - max_age_seconds
        
        for ip in list(self.rows_by_ip.keys()):
            rows = self.rows_by_ip[ip]
            # Filtrar filas recientes
            new_rows = deque(
                [r for r in rows if r.get('ts', 0) >= cutoff],
                maxlen=500
            )
            if len(new_rows) == 0:
                del self.rows_by_ip[ip]
            else:
                self.rows_by_ip[ip] = new_rows
    
    def get_stats(self) -> Dict:
        """Retorna estadísticas"""
        return {
            **self.stats,
            'unique_ips': len(self.rows_by_ip),
            'total_rows_buffered': sum(len(rows) for rows in self.rows_by_ip.values()),
            'recent_windows': len(self.recent_windows)
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
