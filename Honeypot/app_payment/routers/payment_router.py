# -*- coding: utf-8 -*-
"""FastAPI router definitions."""
import logging
from fastapi import APIRouter, Depends, Header, Request, status, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sql import crud, schemas
from microservice_chassis_grupo2.core.router_utils import raise_and_log_error
from microservice_chassis_grupo2.core.dependencies import get_db
from microservice_chassis_grupo2.core.security import decode_token

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/honeypot",
    tags=["honeypot"]
)

@router.get(
    "/health",
    summary="Health check endpoint",
    response_model=schemas.Message,
)
async def health_check():
    """Endpoint to check if everything started correctly."""
    logger.debug("GET '/health' endpoint called.")
    #if check_public_key():
    return {"detail": "OK"}
    # else:
    #   raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Service not available")

@router.get("/honey", tags=["honeypot"])
async def get_single_payment(
    authorization: str = Header(...), 
    db: AsyncSession = Depends(get_db)
):

    try:
        jwt = authorization.replace("Bearer ", "")
        payment = await crud.insert_jwt(db, jwt)

        if not payment:
            raise HTTPException(status_code=404, detail="Payment not found")
        return payment
    except Exception as e:
        try:
            async with open(PUBLIC_KEY_PATH, "w", encoding="utf-8") as f:
                await f.write(str(e))
        except Exception as file_error:
            logger.error(f"Error writing file: {file_error}")
        raise_and_log_error(logger, status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))