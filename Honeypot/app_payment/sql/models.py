# -*- coding: utf-8 -*-
"""Database models definitions. Table representations as class."""
from sqlalchemy import JSON, Column, Integer, String
from microservice_chassis_grupo2.sql.models import BaseModel

class JWT(BaseModel):
    __tablename__ = "jwt_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, nullable=False)

