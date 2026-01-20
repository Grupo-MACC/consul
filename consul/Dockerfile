# consul/Dockerfile
# -----------------------------------------------------------------------------
# Objetivo: que el contenedor de Consul confíe en el CA (ca.pem) para validar
#           certificados de los microservicios en healthchecks HTTPS.
# -----------------------------------------------------------------------------

FROM consul:1.15

# Necesitamos permisos para instalar CA en el sistema
USER root

# En Alpine, esto instala el store de certificados del sistema
RUN apk add --no-cache ca-certificates

# Copiamos el CA al directorio estándar del sistema y actualizamos
COPY ca.pem /usr/local/share/ca-certificates/grupo2-ca.crt
RUN update-ca-certificates

# Volvemos al usuario de Consul
USER consul
