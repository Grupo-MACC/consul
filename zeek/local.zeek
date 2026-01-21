# Zeek local configuration for ADS capture
# Habilita los logs necesarios para el dataset

@load base/protocols/conn
@load base/protocols/ssl
@load base/files/hash

# Configuración de logs
redef Log::default_rotation_interval = 1hr;

# Configurar campos adicionales que necesitamos
event zeek_init()
{
    print "Zeek ADS Capture initialized";
    print fmt("Capturing traffic on port %s", getenv("CONSUL_PORT"));
}

# Log de conexiones completadas
event connection_state_remove(c: connection)
{
    # Solo nos interesan conexiones al puerto de Consul
    if (c$id$resp_p == 8501/tcp)
    {
        # Zeek automáticamente escribe a conn.log
    }
}
