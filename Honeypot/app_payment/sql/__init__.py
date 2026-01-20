import logging
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sql import models

logger = logging.getLogger(__name__)

async def init_db(session: AsyncSession):
    logger.info("🔧 Inicializando datos base para Honeypot...")

    result = await session.execute(
        select(models.JWT).where(models.JWT.token == "PRUEBA_ADMIN_TOKEN")
    )
    admin_jwt = result.scalar_one_or_none()

    if not admin_jwt:
        admin_jwt = models.JWT(
            token="PRUEBA_ADMIN_TOKEN"
        )
        session.add(admin_jwt)
        await session.commit()