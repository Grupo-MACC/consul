# Payment/app_payment/sql/schemas.py
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Literal

class Message(BaseModel):
    detail: Optional[str] = Field(example="error or success message")

PaymentStatus = Literal["Initiated","Authorized","Captured","Refunded","Failed","Canceled"]

class JWTBase(BaseModel):
    token: str

class JWTCreate(JWTBase):
    pass
