# -----------------------------------------------------------------------------
# Configuración de Consul (server single-node) con HTTPS
# -----------------------------------------------------------------------------

datacenter = "dc1"
data_dir   = "/consul/data"

server           = true
bootstrap_expect = 1

ui_config {
  enabled = true
}

client_addr = "0.0.0.0"
bind_addr = "{{ GetInterfaceIP \"eth0\" }}"

# IMPORTANTE:
# - Activamos HTTPS en 8501 (lo recomendado).
# - Desactivamos HTTP (-1) para forzar cifrado.
ports {
  http  = -1
  https = 8501
  dns   = 8600
}

addresses {
  https = "0.0.0.0"
}

# TLS: material criptográfico + política
# En tu caso queremos HTTPS cifrado y que los clientes verifiquen el servidor,
# pero SIN pedir certificado cliente (no mTLS).
tls {
  defaults {
    ca_file   = "/consul/certs/ca.pem"
    cert_file = "/consul/certs/consul/consul-cert.pem"
    key_file  = "/consul/certs/consul/consul-key.pem"
  }

  https {
    verify_incoming = false
  }
}
