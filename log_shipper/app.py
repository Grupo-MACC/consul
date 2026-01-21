"""
Log Shipper - Recibe notificaciones de restart de microservicios
Endpoint simple que almacena eventos de Docker para el Merger
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from collections import deque
from dataclasses import dataclass, asdict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Configuración
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
MAX_EVENTS = 10000  # Máximo eventos en memoria

# Logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("log-shipper")

app = FastAPI(
    title="Log Shipper",
    description="Recibe notificaciones de restart de microservicios",
    version="1.0.0"
)

# ============================================
# MODELOS
# ============================================

class ServiceNotification(BaseModel):
    """
    Notificación que envían los microservicios cuando inician/reinician.
    Los microservicios deben llamar a POST /notify al arrancar.
    """
    service_name: str           # Nombre del servicio (auth, order, payment, etc.)
    container_ip: str           # IP del contenedor
    container_name: Optional[str] = None  # Nombre del contenedor Docker
    event_type: str = "start"   # start, restart, stop
    timestamp: Optional[float] = None  # Unix timestamp, si no se proporciona se usa now()

class RestartEvent(BaseModel):
    """Notificación de restart de un microservicio (legacy, usar ServiceNotification)"""
    container_name: str
    container_ip: str
    timestamp: Optional[float] = None  # Unix timestamp, si no se proporciona se usa now()
    event_type: str = "restart"  # restart, start, stop
    service_name: Optional[str] = None  # Nombre del servicio en Consul

class EventsQuery(BaseModel):
    """Query para obtener eventos"""
    since_timestamp: Optional[float] = None
    container_ip: Optional[str] = None
    limit: int = 100

# ============================================
# ESTADO
# ============================================

@dataclass
class StoredEvent:
    container_name: str
    container_ip: str
    timestamp: float
    event_type: str
    service_name: str

@dataclass
class ContainerInfo:
    """Información de un contenedor registrado"""
    container_ip: str
    container_name: str
    service_name: str
    start_time: float  # Timestamp del último start
    last_event_time: float  # Timestamp del último evento
    last_event_type: str  # Tipo del último evento

class EventStore:
    def __init__(self, max_events: int = MAX_EVENTS):
        self.events: deque = deque(maxlen=max_events)
        # Índice por IP para búsqueda rápida
        self.by_ip: Dict[str, List[StoredEvent]] = {}
        # Último evento por IP
        self.last_by_ip: Dict[str, StoredEvent] = {}
        # Info de contenedores registrados (IP -> ContainerInfo)
        self.containers: Dict[str, ContainerInfo] = {}
        # Estadísticas
        self.stats = {
            "total_received": 0,
            "restarts": 0,
            "starts": 0,
            "stops": 0
        }
    
    def add_event(self, event: RestartEvent) -> StoredEvent:
        ts = event.timestamp or datetime.now().timestamp()
        
        stored = StoredEvent(
            container_name=event.container_name,
            container_ip=event.container_ip,
            timestamp=ts,
            event_type=event.event_type,
            service_name=event.service_name or event.container_name
        )
        
        self.events.append(stored)
        
        # Actualizar índice por IP
        if event.container_ip not in self.by_ip:
            self.by_ip[event.container_ip] = []
        self.by_ip[event.container_ip].append(stored)
        
        # Mantener solo últimos 100 por IP
        if len(self.by_ip[event.container_ip]) > 100:
            self.by_ip[event.container_ip] = self.by_ip[event.container_ip][-100:]
        
        # Actualizar último por IP
        self.last_by_ip[event.container_ip] = stored
        
        # Actualizar info del contenedor
        if event.container_ip in self.containers:
            # Actualizar contenedor existente
            container = self.containers[event.container_ip]
            container.last_event_time = ts
            container.last_event_type = event.event_type
            # Si es start o restart, actualizar start_time
            if event.event_type in ("start", "restart"):
                container.start_time = ts
        else:
            # Nuevo contenedor
            self.containers[event.container_ip] = ContainerInfo(
                container_ip=event.container_ip,
                container_name=event.container_name,
                service_name=event.service_name or event.container_name,
                start_time=ts,
                last_event_time=ts,
                last_event_type=event.event_type
            )
        
        # Estadísticas
        self.stats["total_received"] += 1
        if event.event_type == "restart":
            self.stats["restarts"] += 1
        elif event.event_type == "start":
            self.stats["starts"] += 1
        elif event.event_type == "stop":
            self.stats["stops"] += 1
        
        return stored
    
    def get_events_since(self, since_ts: float, limit: int = 100) -> List[StoredEvent]:
        """Obtiene eventos desde un timestamp"""
        result = []
        for event in reversed(self.events):
            if event.timestamp >= since_ts:
                result.append(event)
                if len(result) >= limit:
                    break
        return list(reversed(result))
    
    def get_events_for_ip(self, ip: str, since_ts: Optional[float] = None) -> List[StoredEvent]:
        """Obtiene eventos para una IP específica"""
        events = self.by_ip.get(ip, [])
        if since_ts:
            events = [e for e in events if e.timestamp >= since_ts]
        return events
    
    def get_last_event_for_ip(self, ip: str) -> Optional[StoredEvent]:
        """Obtiene el último evento para una IP"""
        return self.last_by_ip.get(ip)
    
    def get_recent_event_for_ip(self, ip: str, window_seconds: float = 60) -> bool:
        """Verifica si hay un evento reciente para una IP"""
        last = self.last_by_ip.get(ip)
        if not last:
            return False
        now = datetime.now().timestamp()
        return (now - last.timestamp) <= window_seconds
    
    def get_container_info(self, ip: str) -> Optional[ContainerInfo]:
        """Obtiene información del contenedor por IP"""
        return self.containers.get(ip)

store = EventStore()

# ============================================
# ENDPOINTS
# ============================================

@app.get("/health")
async def health():
    """Health check"""
    return {
        "status": "healthy",
        "events_stored": len(store.events),
        "ips_tracked": len(store.by_ip)
    }

@app.get("/stats")
async def get_stats():
    """Estadísticas del servicio"""
    return {
        "stats": store.stats,
        "events_in_memory": len(store.events),
        "unique_ips": len(store.by_ip)
    }

@app.post("/restart")
async def receive_restart(event: RestartEvent):
    """
    Recibe notificación de restart de un microservicio
    Los microservicios llaman a este endpoint cuando se reinician
    """
    stored = store.add_event(event)
    
    logger.info(
        f"Evento recibido: {event.event_type} - "
        f"{event.container_name} ({event.container_ip})"
    )
    
    return {
        "status": "ok",
        "event_id": id(stored),
        "timestamp": stored.timestamp
    }

@app.get("/events")
async def get_events(
    since: Optional[float] = None,
    ip: Optional[str] = None,
    limit: int = 100
):
    """
    Obtiene eventos almacenados
    - since: timestamp Unix desde el cual obtener eventos
    - ip: filtrar por IP del contenedor
    - limit: máximo número de eventos
    """
    if ip:
        events = store.get_events_for_ip(ip, since)
    elif since:
        events = store.get_events_since(since, limit)
    else:
        events = list(store.events)[-limit:]
    
    return {
        "events": [asdict(e) for e in events],
        "count": len(events)
    }

@app.get("/events/last/{ip}")
async def get_last_event(ip: str):
    """Obtiene el último evento para una IP"""
    event = store.get_last_event_for_ip(ip)
    if not event:
        return {"event": None, "found": False}
    
    return {
        "event": asdict(event),
        "found": True,
        "seconds_ago": datetime.now().timestamp() - event.timestamp
    }

@app.get("/events/recent/{ip}")
async def check_recent_event(ip: str, window: float = 60):
    """
    Verifica si hay un evento reciente para una IP
    Útil para el Merger para calcular recent_docker_event
    """
    has_recent = store.get_recent_event_for_ip(ip, window)
    last_event = store.get_last_event_for_ip(ip)
    
    result = {
        "ip": ip,
        "has_recent_event": has_recent,
        "window_seconds": window
    }
    
    if last_event:
        result["last_event_timestamp"] = last_event.timestamp
        result["seconds_since_last"] = datetime.now().timestamp() - last_event.timestamp
    
    return result

@app.get("/status/all")
async def get_all_container_status():
    """
    Obtiene el estado de todos los contenedores conocidos
    Útil para el Merger para tener contexto completo
    """
    now = datetime.now().timestamp()
    result = {}
    
    for ip, last_event in store.last_by_ip.items():
        seconds_since = now - last_event.timestamp
        result[ip] = {
            "container_name": last_event.container_name,
            "service_name": last_event.service_name,
            "last_event_type": last_event.event_type,
            "last_event_timestamp": last_event.timestamp,
            "seconds_since_last_event": seconds_since,
            "recent_activity": seconds_since <= 60
        }
    
    return {
        "containers": result,
        "total": len(result)
    }


# ============================================
# ENDPOINTS PARA MICROSERVICIOS
# ============================================

@app.post("/notify")
async def notify_service_event(notification: ServiceNotification):
    """
    Endpoint principal para que los microservicios notifiquen su inicio/restart.
    
    Los microservicios deben llamar a este endpoint cuando:
    - Inician por primera vez (event_type: "start")
    - Se reinician (event_type: "restart")
    - Se detienen (event_type: "stop") - opcional
    
    Ejemplo de llamada desde un microservicio (Python):
    ```python
    import requests
    import socket
    
    def notify_start():
        requests.post("http://log-shipper:8081/notify", json={
            "service_name": "auth",
            "container_ip": socket.gethostbyname(socket.gethostname()),
            "event_type": "start"
        })
    ```
    """
    # Convertir a RestartEvent para reutilizar lógica existente
    event = RestartEvent(
        container_name=notification.container_name or notification.service_name,
        container_ip=notification.container_ip,
        timestamp=notification.timestamp,
        event_type=notification.event_type,
        service_name=notification.service_name
    )
    
    stored = store.add_event(event)
    
    logger.info(
        f"Notificación recibida: {notification.event_type} - "
        f"{notification.service_name} ({notification.container_ip})"
    )
    
    return {
        "status": "ok",
        "service": notification.service_name,
        "ip": notification.container_ip,
        "event_type": notification.event_type,
        "timestamp": stored.timestamp
    }


# ============================================
# ENDPOINTS PARA EL MERGER
# ============================================

# ============================================
# ENDPOINTS PARA EL MERGER
# ============================================

@app.get("/container/info/{ip}")
async def get_container_info(ip: str):
    """
    Obtiene información del contenedor por IP.
    El Merger usa esto para calcular:
    - recent_docker_event: si hubo evento en últimos 60s
    - time_since_container_start: segundos desde el start
    """
    now = datetime.now().timestamp()
    container = store.get_container_info(ip)
    
    if not container:
        return {
            "found": False,
            "ip": ip,
            "recent_event": False,
            "container_start_time": None,
            "container_name": None
        }
    
    # Verificar si hay evento reciente (últimos 60s)
    recent_event = (now - container.last_event_time) <= 60
    
    return {
        "found": True,
        "ip": ip,
        "container_name": container.container_name,
        "service_name": container.service_name,
        "container_start_time": container.start_time,
        "last_event_time": container.last_event_time,
        "last_event_type": container.last_event_type,
        "recent_event": recent_event,
        "seconds_since_start": now - container.start_time,
        "seconds_since_last_event": now - container.last_event_time
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)
