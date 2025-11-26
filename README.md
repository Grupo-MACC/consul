"# Consul Service Discovery

## Overview

Consul is used for service discovery in this microservices architecture. Each service registers itself with Consul on startup and deregisters on shutdown.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CONSUL (Service Discovery)                │
│                      http://localhost:8500                   │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
    ┌─────────┐          ┌─────────┐          ┌─────────┐
    │  Auth   │          │  Order  │          │ Machine │
    │  :5004  │          │  :5000  │          │  :5001  │
    └─────────┘          └─────────┘          └─────────┘
         │                    │                    │
         ▼                    ▼                    ▼
    ┌─────────┐          ┌─────────┐          ┌─────────┐
    │ Payment │          │Delivery │          │ HAProxy │
    │  :5003  │          │  :5002  │          │   :443  │
    └─────────┘          └─────────┘          └─────────┘
```

## Service Registration

Each service registers with Consul using the following information:
- **Service Name**: Logical name (e.g., "auth", "order", "machine")
- **Service ID**: Unique identifier (e.g., "auth-1", "order-1")
- **Port**: Service port number
- **Health Check**: HTTP health check endpoint

## Consul Client

The `consul_client.py` module provides:
- `register_service()`: Register a service with Consul
- `deregister_service()`: Deregister a service from Consul
- `discover_service()`: Find a service by name
- `get_service_url()`: Get service URL with retry and fallback

## HAProxy Integration

HAProxy uses Consul DNS for service discovery:
```
resolvers consul
    nameserver consul consul:8600
    
backend order_service
    server-template order 1 order.service.consul:5000 resolvers consul
```

## API Endpoints

### Consul UI
- URL: http://localhost:8500

### Service Catalog
```bash
# List all services
curl http://localhost:8500/v1/catalog/services

# Get specific service
curl http://localhost:8500/v1/catalog/service/auth
```

### Health Checks
```bash
# Check service health
curl http://localhost:8500/v1/health/service/auth?passing=true
```

## Environment Variables

Each service uses these environment variables:
- `CONSUL_HOST`: Consul host (default: consul)
- `CONSUL_PORT`: Consul port (default: 8500)
- `SERVICE_NAME`: Service name for registration
- `SERVICE_PORT`: Service port number
- `SERVICE_ID`: Unique service instance ID

## Testing

After starting the services, verify registration:
```bash
curl http://localhost:8500/v1/catalog/services | jq
```

Expected output:
```json
{
  "consul": [],
  "auth": ["fastapi", "auth"],
  "order": ["fastapi", "order"],
  "machine": ["fastapi", "machine"],
  "delivery": ["fastapi", "delivery"],
  "payment": ["fastapi", "payment"]
}
```" 
