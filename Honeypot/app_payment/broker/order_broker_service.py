import httpx
import json
import logging
from microservice_chassis_grupo2.core.rabbitmq_core import declare_exchange, PUBLIC_KEY_PATH, declare_exchange_logs
from aio_pika import Message, connect_robust
from consul_client import get_service_url
import os

logger = logging.getLogger(__name__)

RABBITMQ_HOST = (
        f"amqp://{os.getenv('RABBITMQ_USER', 'guest')}:"
        f"{os.getenv('RABBITMQ_PASSWORD', 'guest')}@"
        f"{os.getenv('RABBITMQ_HOST', 'localhost')}/"
)

async def get_channel():
    logger.info("🐝 Conectando a RabbitMQ...")
    connection = await connect_robust(RABBITMQ_HOST)
    channel = await connection.channel()
    
    return connection, channel

#region auth
async def consume_auth_events():
    logger.info("🐝 Iniciando consumidor de eventos de Auth...")
    _, channel = await get_channel()
    
    exchange = await declare_exchange(channel)
    logger.info("[honeypot_queue] 🐝 Consumiendo eventos de Auth desde RabbitMQ")
    honeypot_queue = await channel.declare_queue('honeypot_queue', durable=True)
    await honeypot_queue.bind(exchange, routing_key="auth.running")
    await honeypot_queue.bind(exchange, routing_key="auth.not_running")
    
    await honeypot_queue.consume(handle_auth_events)

async def handle_auth_events(message):
    async with message.process():
        data = json.loads(message.body)
        if data["status"] == "running":
            try:
                # Use Consul to discover auth service (no fallback)
                auth_service_url = await get_service_url("auth")
                logger.info(f"[honeypot] 🔍 Auth descubierto via Consul: {auth_service_url}")
                
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        f"{auth_service_url}/auth/public-key"
                    )
                    response.raise_for_status()
                    public_key = response.text
                    
                    async with open(PUBLIC_KEY_PATH, "w", encoding="utf-8") as f:
                        await f.write(public_key)
                    logger.info(f"[honeypot] ✅ Clave pública de Auth guardada en {PUBLIC_KEY_PATH}")
                    await publish_to_logger(
                        message={
                            "message": "Clave pública de Auth guardada",
                            "path": PUBLIC_KEY_PATH,
                        },
                        topic="honeypot.info",
                    )
            except Exception as exc:
                logger.error(f"[honeypot] ❌ Error obteniendo clave pública de Auth: {exc}")
                await publish_to_logger(
                    message={
                        "message": "Error obteniendo clave pública de Auth",
                        "error": str(exc),
                    },
                    topic="honeypot.error",
                )

#region logger
async def publish_to_logger(message, topic):
    connection = None
    try:
        connection, channel = await get_channel()
        
        exchange = await declare_exchange_logs(channel)
        
        # Asegúrate de que el mensaje tenga estos campos
        log_data = {
            "measurement": "logs",
            "service": topic.split('.')[0],
            "severity": topic.split('.')[1],
            **message
        }

        msg = Message(
            body=json.dumps(log_data).encode(), 
            content_type="application/json", 
            delivery_mode=2
        )
        await exchange.publish(message=msg, routing_key=topic)
        
    except Exception as e:
        print(f"Error publishing to logger: {e}")
    finally:
        if connection:
            await connection.close()

