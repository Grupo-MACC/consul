"""
Pipeline integrado para detección de Consul Poisoning
=====================================================

Este módulo integra:
- RealtimeDatasetGenerator: Genera filas formato dataset_10k_final.csv
- RealtimeWindowGenerator: Transforma filas a ventanas agregadas

Uso:
    from realtime_pipeline import ConsulPoisoningPipeline
    
    pipeline = ConsulPoisoningPipeline()
    
    # Cuando llega una conexión Zeek + SSL
    row = pipeline.process_connection(zeek_conn, zeek_ssl)
    
    # Obtener ventana para predicción
    window = pipeline.get_window_for_prediction(ip)
"""

import time
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import deque

# Imports que funcionan tanto como módulo como script directo
try:
    from .realtime_dataset_generator import (
        RealtimeDatasetGenerator,
        ZeekConnection,
        ZeekSSL,
        DockerEvent,
        DatasetRow
    )
    from .realtime_window_generator import (
        RealtimeWindowGenerator,
        WindowConfig,
        prepare_window_for_model,
        window_to_numpy
    )
except ImportError:
    from realtime_dataset_generator import (
        RealtimeDatasetGenerator,
        ZeekConnection,
        ZeekSSL,
        DockerEvent,
        DatasetRow
    )
    from realtime_window_generator import (
        RealtimeWindowGenerator,
        WindowConfig,
        prepare_window_for_model,
        window_to_numpy
    )

logger = logging.getLogger(__name__)


class ConsulPoisoningPipeline:
    """
    Pipeline completo para detección de Consul Poisoning en tiempo real.
    
    Flujo:
    1. Recibe conexiones Zeek (conn.log + ssl.log)
    2. Genera filas con todas las features (formato dataset_10k_final.csv)
    3. Acumula filas en ventanas temporales
    4. Genera ventanas agregadas para el modelo
    
    El modelo espera ventanas de 30 segundos con estadísticas agregadas
    (mean, std, max) de las features base.
    """
    
    def __init__(self, window_config: Optional[WindowConfig] = None):
        # Generador de filas base
        self.dataset_generator = RealtimeDatasetGenerator()
        
        # Generador de ventanas
        self.window_generator = RealtimeWindowGenerator(window_config)
        
        # Stats
        self.stats = {
            'connections_processed': 0,
            'rows_generated': 0,
            'windows_generated': 0,
            'predictions_made': 0
        }
        
        # Última ventana generada por IP (para visualización/debug)
        self.last_windows: Dict[str, Dict] = {}
        
        logger.info("ConsulPoisoningPipeline initialized")
        logger.info(f"  Timeout: {self.window_generator.config.timeout_seconds}s")
        logger.info(f"  Min connections: {self.window_generator.config.min_connections}")
    
    def process_connection(
        self, 
        zeek_conn: ZeekConnection, 
        zeek_ssl: Optional[ZeekSSL] = None
    ) -> Tuple[DatasetRow, Optional[Dict]]:
        """
        Procesa una conexión y genera la fila del dataset.
        Si cambia la IP, cierra y devuelve la ventana anterior.
        
        Args:
            zeek_conn: Conexión parseada de conn.log
            zeek_ssl: Datos SSL parseados de ssl.log (opcional)
            
        Returns:
            Tupla (DatasetRow, ventana_cerrada o None)
        """
        # Generar fila con todas las features
        row = self.dataset_generator.process_connection(zeek_conn, zeek_ssl)
        
        # Convertir a dict para el generador de ventanas
        row_dict = row.to_dict_with_zeek_columns()
        
        # Añadir al buffer de ventanas (puede cerrar ventana de IP anterior)
        closed_window = self.window_generator.add_row(row_dict)
        
        self.stats['connections_processed'] += 1
        self.stats['rows_generated'] += 1
        
        if closed_window:
            self.stats['windows_generated'] += 1
            ip = closed_window.get('id.orig_h')
            if ip:
                self.last_windows[ip] = closed_window
            logger.info(f"Window auto-closed for {ip} (IP change)")
        
        return row, closed_window
    
    def add_docker_event(self, event: DockerEvent):
        """
        Añade un evento de Docker al pipeline.
        
        Args:
            event: Evento Docker (restart, start, etc.)
        """
        self.dataset_generator.add_docker_event(event)
        logger.debug(f"Docker event added: {event.action} for {event.container_name}")
    
    def get_window_for_prediction(self, ip: str) -> Optional[Dict]:
        """
        Cierra y obtiene la ventana para una IP, lista para predicción.
        Nota: Esto cierra la ventana, no se puede volver a obtener.
        
        Args:
            ip: IP origen
            
        Returns:
            Diccionario con features de ventana, o None si no hay suficientes datos
        """
        window = self.window_generator.generate_window_for_ip(ip)
        
        if window:
            self.stats['windows_generated'] += 1
            self.last_windows[ip] = window
            logger.debug(f"Window closed for {ip}: {window.get('n_connections')} connections")
            
        return window
    
    def get_all_windows(self) -> List[Dict]:
        """
        Fuerza el cierre de todas las ventanas abiertas.
        Útil al finalizar el procesamiento.
        
        Returns:
            Lista de ventanas listas para predicción
        """
        windows = self.window_generator.force_close_all()
        
        for w in windows:
            ip = w.get('id.orig_h')
            if ip:
                self.last_windows[ip] = w
        
        self.stats['windows_generated'] += len(windows)
        
        if windows:
            logger.info(f"Force-closed {len(windows)} windows")
            
        return windows
    
    def check_timeouts(self) -> List[Dict]:
        """
        Verifica timeouts y cierra ventanas inactivas (>15 segundos).
        Debe llamarse periódicamente (ej: cada segundo).
        
        Returns:
            Lista de ventanas cerradas por timeout
        """
        windows = self.window_generator.check_timeouts()
        
        for w in windows:
            ip = w.get('id.orig_h')
            if ip:
                self.last_windows[ip] = w
                logger.info(f"Window closed by timeout for {ip}")
        
        self.stats['windows_generated'] += len(windows)
        
        return windows
    
    def get_pending_windows(self) -> List[Dict]:
        """
        Obtiene ventanas pendientes de enviar al modelo.
        
        Returns:
            Lista de ventanas listas
        """
        return self.window_generator.get_pending_windows()
    
    def prepare_for_model(
        self, 
        window: Dict, 
        model_features: Optional[List[str]] = None
    ) -> Dict:
        """
        Prepara una ventana para enviar al modelo.
        
        Args:
            window: Ventana generada
            model_features: Lista de features que espera el modelo (None = todas)
            
        Returns:
            Diccionario con solo las features del modelo
        """
        return prepare_window_for_model(window, model_features)
    
    def get_stats(self) -> Dict:
        """Retorna estadísticas del pipeline"""
        return {
            **self.stats,
            'dataset_generator_stats': self.dataset_generator.stats.copy(),
            'window_generator_stats': self.window_generator.get_stats()
        }
    
    def cleanup_old_data(self, max_age_seconds: float = 300):
        """
        Limpia datos antiguos de los buffers.
        
        Args:
            max_age_seconds: Antigüedad máxima a mantener
        """
        self.dataset_generator.cleanup_old_data(max_age_seconds)
        self.window_generator.clear_old_data(max_age_seconds)


# =============================================================================
# Funciones de integración con app.py existente
# =============================================================================

def create_pipeline_from_env() -> ConsulPoisoningPipeline:
    """
    Crea pipeline con configuración desde variables de entorno.
    """
    import os
    
    timeout_seconds = float(os.getenv('WINDOW_TIMEOUT_SECONDS', '15.0'))
    min_connections = int(os.getenv('MIN_CONNECTIONS_PER_WINDOW', '1'))
    
    config = WindowConfig(
        timeout_seconds=timeout_seconds,
        min_connections=min_connections
    )
    
    return ConsulPoisoningPipeline(config)


def convert_old_connection_to_new(old_conn, old_ssl=None) -> Tuple[ZeekConnection, Optional[ZeekSSL]]:
    """
    Convierte objetos de conexión del merger antiguo al nuevo formato.
    
    Esta función permite usar el nuevo pipeline sin cambiar todo el código de parseo.
    """
    new_conn = ZeekConnection(
        ts=old_conn.ts,
        uid=old_conn.uid,
        orig_h=old_conn.orig_h,
        orig_p=old_conn.orig_p,
        resp_h=old_conn.resp_h,
        resp_p=old_conn.resp_p,
        proto=getattr(old_conn, 'proto', 'tcp'),
        duration=old_conn.duration,
        orig_bytes=old_conn.orig_bytes,
        resp_bytes=old_conn.resp_bytes,
        conn_state=getattr(old_conn, 'conn_state', 'SF'),
        orig_pkts=getattr(old_conn, 'orig_pkts', 0),
        resp_pkts=getattr(old_conn, 'resp_pkts', 0),
        missed_bytes=getattr(old_conn, 'missed_bytes', 0)
    )
    
    new_ssl = None
    if old_ssl:
        new_ssl = ZeekSSL(
            ts=old_ssl.ts,
            uid=old_ssl.uid,
            version=getattr(old_ssl, 'version', 'TLSv12'),
            cipher=getattr(old_ssl, 'cipher', ''),
            server_name=getattr(old_ssl, 'server_name', ''),
            ja3=old_ssl.ja3,
            ja3s=getattr(old_ssl, 'ja3s', ''),
            resumed=getattr(old_ssl, 'resumed', False),
            established=getattr(old_ssl, 'established', True)
        )
    
    return new_conn, new_ssl


# =============================================================================
# Ejemplo de uso
# =============================================================================

def example_usage():
    """
    Ejemplo de cómo usar el pipeline.
    """
    # Crear pipeline
    pipeline = ConsulPoisoningPipeline()
    
    # Simular conexiones
    for i in range(10):
        conn = ZeekConnection(
            ts=time.time() + i * 0.5,
            uid=f"uid-{i}",
            orig_h="10.0.0.100",
            orig_p=50000 + i,
            resp_h="10.0.0.1",
            resp_p=8500,  # Consul
            duration=0.01,
            orig_bytes=100,
            resp_bytes=500
        )
        
        ssl = ZeekSSL(
            ts=conn.ts,
            uid=conn.uid,
            ja3="304734bb1c086c3453b387400cf83f11"  # JA3 conocido
        )
        
        # Procesar conexión
        row = pipeline.process_connection(conn, ssl)
        print(f"Row {i}: burst_score={row.burst_score:.3f}, conn_count_10s={row.conn_count_10s}")
    
    # Obtener ventana para predicción
    window = pipeline.get_window_for_prediction("10.0.0.100")
    
    if window:
        print("\nVentana generada:")
        print(f"  IP: {window.get('id.orig_h')}")
        print(f"  Connections: {window.get('n_connections')}")
        print(f"  burst_score_mean: {window.get('burst_score_mean', 0):.3f}")
        print(f"  burst_intensity: {window.get('burst_intensity', 0):.3f}")
        print(f"  temporal_regularity: {window.get('temporal_regularity', 0):.3f}")
        print(f"  heuristic_attack_score: {window.get('heuristic_attack_score', 0):.3f}")
    else:
        print("\nNo hay suficientes datos para generar ventana")
    
    # Stats
    print(f"\nStats: {pipeline.get_stats()}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    example_usage()
