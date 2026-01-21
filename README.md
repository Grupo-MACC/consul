# Consul Service Discovery + ADS (Attack Detection System)

## Overview

Sistema de Service Discovery con Consul integrado con un sistema de detección de ataques (ADS) que detecta y mitiga automáticamente ataques de **Consul Poisoning**.

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         INFRAESTRUCTURA AWS                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │              CONSUL SERVICE (10.1.11.40)                         │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────────┐  ┌─────────────┐     │    │
│  │  │ Consul  │  │  Zeek   │  │   Merger    │  │ Log-Shipper │     │    │
│  │  │ :8501   │  │ (NIDS)  │  │   :8082     │  │    :8081    │     │    │
│  │  └────┬────┘  └────┬────┘  └──────┬──────┘  └─────────────┘     │    │
│  │       │            │              │                              │    │
│  │       │    ┌───────┴──────┐       │                              │    │
│  │       │    │  Zeek Logs   │───────┘                              │    │
│  │       │    └──────────────┘                                      │    │
│  └───────┼──────────────────────────────────────────────────────────┘    │
│          │                                                               │
│          │  HTTPS/TLS                                                    │
│          ▼                                                               │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                ADS SERVER (10.1.12.10)                           │    │
│  │  ┌──────────────────────────────────────────────────────────┐   │    │
│  │  │                    ADS Server :8083                       │   │    │
│  │  │  ┌────────────────┐  ┌────────────────┐  ┌────────────┐  │   │    │
│  │  │  │  ML Model      │  │  Heurísticas   │  │  Auto      │  │   │    │
│  │  │  │  (Isolation    │  │  (Consul       │  │  Deregister│  │   │    │
│  │  │  │   Forest)      │  │   Poisoning)   │  │            │  │   │    │
│  │  │  └────────────────┘  └────────────────┘  └────────────┘  │   │    │
│  │  └──────────────────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Configuración SSH

Añade esto a tu `~/.ssh/config`:

```bash
Host bastion
    HostName 100.30.63.156
    User ubuntu
    IdentityFile ~/.ssh/key.pem

Host consul_service
    HostName 10.1.11.40
    User ubuntu
    IdentityFile ~/.ssh/key.pem
    ProxyJump bastion

Host ads_server
    HostName 10.1.12.10
    User ubuntu
    IdentityFile ~/.ssh/key.pem
    ProxyJump bastion
```

---

## 🧪 PRUEBAS DE TRÁFICO

### Prerequisitos

```bash
# Verificar que los servicios están corriendo
ssh consul_service 'sudo docker ps'
ssh ads_server 'sudo docker ps'

# Ver logs en tiempo real (en terminales separadas)
ssh consul_service 'sudo docker logs -f merger'
ssh ads_server 'sudo docker logs -f ads-server'
```

---

## ✅ TRÁFICO NORMAL (No debe generar alerta)

Los microservicios hacen peticiones **espaciadas** (varios segundos entre cada una):

### Ejemplo 1: GET aislado (consulta de servicios)
```bash
ssh ads_server 'curl -sk https://10.1.11.40:8501/v1/catalog/services'
```

### Ejemplo 2: PUT aislado (registro de microservicio)
```bash
ssh ads_server 'curl -sk -X PUT "https://10.1.11.40:8501/v1/agent/service/register" \
  -H "Content-Type: application/json" \
  -d "{\"ID\": \"order-service\", \"Name\": \"order\", \"Address\": \"10.0.1.5\", \"Port\": 8080}"'
```

### Ejemplo 3: Tráfico típico de microservicio (espaciado)
```bash
ssh ads_server '
echo "1. GET servicios - $(date +%H:%M:%S)"
curl -sk https://10.1.11.40:8501/v1/catalog/services > /dev/null

sleep 8

echo "2. PUT registro - $(date +%H:%M:%S)"
curl -sk -X PUT "https://10.1.11.40:8501/v1/agent/service/register" \
  -H "Content-Type: application/json" \
  -d "{\"ID\": \"payment-svc\", \"Name\": \"payment\", \"Address\": \"10.0.2.10\", \"Port\": 5003}"

sleep 12

echo "3. GET health check - $(date +%H:%M:%S)"
curl -sk https://10.1.11.40:8501/v1/agent/checks > /dev/null

echo "COMPLETADO"
'
```

**Resultado esperado en logs de ADS:**
```
Tráfico normal: burst_score=0.0, espaciado=True
Heurística override: tráfico normal espaciado, ignorando modelo ML
```

---

## 🚨 ATAQUES (Debe generar alerta y auto-deregister)

El ataque **Consul Poisoning** sigue el patrón: **SCAN → INJECT → CHECK** en menos de 2 segundos.

### Ataque 1: Patrón completo Scan-Inject-Check
```bash
ssh ads_server '
echo "========== ATAQUE CONSUL POISONING =========="
echo "1. SCAN - GET catalog/services - $(date +%H:%M:%S)"
curl -sk https://10.1.11.40:8501/v1/catalog/services > /dev/null

echo "2. SCAN - GET agent/services - $(date +%H:%M:%S)"
curl -sk https://10.1.11.40:8501/v1/agent/services > /dev/null

echo "3. SCAN - GET catalog/nodes - $(date +%H:%M:%S)"
curl -sk https://10.1.11.40:8501/v1/catalog/nodes > /dev/null

echo "4. INJECT - PUT servicio malicioso - $(date +%H:%M:%S)"
curl -sk -X PUT "https://10.1.11.40:8501/v1/agent/service/register" \
  -H "Content-Type: application/json" \
  -d "{\"ID\": \"malicious-rds\", \"Name\": \"rds\", \"Address\": \"192.168.66.6\", \"Port\": 3306}"

echo "5. CHECK - GET verificar registro - $(date +%H:%M:%S)"
curl -sk https://10.1.11.40:8501/v1/catalog/service/rds > /dev/null

echo "========== ATAQUE COMPLETADO =========="
'
```

### Ataque 2: Ráfaga de PUTs (registros masivos)
```bash
ssh ads_server '
echo "========== ATAQUE: RAFAGA DE PUTS =========="
for i in 1 2 3 4 5 6; do
  curl -sk -X PUT "https://10.1.11.40:8501/v1/agent/service/register" \
    -H "Content-Type: application/json" \
    -d "{\"ID\": \"attack-$i\", \"Name\": \"malicious\", \"Address\": \"192.168.100.$i\", \"Port\": 900$i}" &
done
wait
echo "6 servicios maliciosos registrados en paralelo"
'
```

### Ataque 3: Escaneo intensivo
```bash
ssh ads_server '
echo "========== ATAQUE: ESCANEO INTENSIVO =========="
for endpoint in catalog/services agent/services catalog/nodes agent/checks catalog/datacenters; do
  echo "Escaneando: $endpoint"
  curl -sk "https://10.1.11.40:8501/v1/$endpoint" > /dev/null &
done
wait
echo "Escaneo completado"
'
```

**Resultado esperado en logs de ADS:**
```
🚨 ATAQUE DETECTADO - IP: 10.1.12.10, Score: 0.850, Confianza: 80.00%
🚨 RESPUESTA AUTOMÁTICA: Confianza 80.00% >= 75.00%
HTTP Request: POST http://10.1.11.40:8082/deregister/10.1.12.10 "HTTP/1.1 200 OK"
✅ RESPUESTA COMPLETADA: X servicios desregistrados de IP 10.1.12.10
```

---

## 📊 Verificar Resultados

### Ver logs del Merger (procesamiento de conexiones)
```bash
ssh consul_service 'sudo docker logs merger --tail 50 2>&1 | grep -E "(Generadas|Timeout|Buffer|WINDOW|ATAQUE)"'
```

### Ver logs del ADS (detección y respuesta)
```bash
ssh ads_server 'sudo docker logs ads-server --tail 50 2>&1 | grep -E "(ATAQUE|Score|Confi|deregister|normal)"'
```

### Ver servicios registrados en Consul
```bash
ssh ads_server 'curl -sk https://10.1.11.40:8501/v1/agent/services | jq "keys"'
```

### Limpiar servicios de prueba
```bash
ssh ads_server '
for svc in order-service payment-svc malicious-rds attack-1 attack-2 attack-3 attack-4 attack-5 attack-6; do
  curl -sk -X PUT "https://10.1.11.40:8501/v1/agent/service/deregister/$svc"
done
echo "Servicios de prueba eliminados"
'
```

---

## ⚙️ Parámetros de Configuración

### Merger (consul_service)
| Variable | Valor | Descripción |
|----------|-------|-------------|
| `WINDOW_SIZE_SECONDS` | 15 | Tiempo máximo de ventana |
| `CLOSE_WINDOW_ON_IP_CHANGE` | true | Cerrar ventana si cambia IP |
| `ADS_SERVER_URL` | http://10.1.12.10:8083/predict | URL del ADS |

### ADS Server
| Variable | Valor | Descripción |
|----------|-------|-------------|
| `ATTACK_THRESHOLD` | 0.5 | Score mínimo para considerar ataque |
| `AUTO_DEREGISTER` | true | Habilitar auto-deregister |
| `AUTO_DEREGISTER_THRESHOLD` | 0.75 | Confianza mínima para auto-deregister |

---

## 🔍 Diferencias Clave: Normal vs Ataque

| Característica | Tráfico Normal | Ataque |
|----------------|----------------|--------|
| **Tiempo entre peticiones** | 5-30+ segundos | < 2 segundos |
| **Patrón** | GET o PUT aislados | SCAN(múltiples GET) → PUT → CHECK |
| **burst_score** | 0.0 | > 0.5 |
| **Conexiones en 10s** | 1-2 | 4-6+ |
| **Resultado** | Ignorado por heurística | Detectado + Auto-deregister |

---

## 📝 Notas

- Las ventanas se cierran por **timeout (15s)** o por **cambio de IP**
- El tráfico espaciado (>5s entre conexiones) se marca como normal automáticamente
- El auto-deregister solo se ejecuta si la confianza es >= 75%
- Los servicios desregistrados se eliminan del catálogo de Consul
