#!/bin/bash
set -e

echo "=== Zeek Capture Service ==="
echo "Interface: ${CAPTURE_INTERFACE}"
echo "Consul Port: ${CONSUL_PORT}"
echo "Log Dir: ${ZEEK_LOG_DIR}"

# Filtro BPF para capturar solo tráfico hacia el puerto de Consul
BPF_FILTER="port ${CONSUL_PORT}"

echo "BPF Filter: ${BPF_FILTER}"
echo "Iniciando Zeek..."

# Ejecutar Zeek en modo live capture
# -C: no verificar checksums
# -i: interfaz
# -f: filtro BPF
# Los logs se escriben en el directorio actual (ZEEK_LOG_DIR)
exec zeek -C -i ${CAPTURE_INTERFACE} \
    -f "${BPF_FILTER}" \
    /opt/zeek/scripts/local.zeek \
    "Site::local_nets += { 172.16.0.0/12, 10.0.0.0/8, 192.168.0.0/16 }"
