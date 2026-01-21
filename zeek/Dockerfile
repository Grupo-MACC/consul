FROM zeek/zeek:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Crear directorios
RUN mkdir -p /opt/zeek/logs /opt/zeek/scripts

# Script de Zeek para capturar tráfico TLS
COPY local.zeek /opt/zeek/scripts/

# Script de entrada
COPY entrypoint.sh /opt/zeek/scripts/
RUN chmod +x /opt/zeek/scripts/entrypoint.sh

ENV CAPTURE_INTERFACE=eth0
ENV CONSUL_PORT=8501
ENV ZEEK_LOG_DIR=/opt/zeek/logs

WORKDIR /opt/zeek/logs

ENTRYPOINT ["/opt/zeek/scripts/entrypoint.sh"]
