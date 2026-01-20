# -*- coding: utf-8 -*-
"""Functions that interact with the database."""
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from . import models

logger = logging.getLogger(__name__)

async def insert_jwt(db: AsyncSession, jwt_data: str):
    new_jwt = models.JWT(token=jwt_data)
    db.add(new_jwt) 
    await db.commit()
    await db.refresh(new_jwt)
    return new_jwt
