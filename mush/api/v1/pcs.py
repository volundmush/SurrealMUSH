import typing

import pydantic
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer

from mush.shared.models.users import UserModel

router = APIRouter()


class UserListSegment(pydantic.BaseModel):
    items: list[UserModel]
    total: int
    offset: int
    limit: int
    has_next: bool


@router.get("/", response_model=UserListSegment)
async def get_users(token: str = Depends(HTTPBearer())):
    pass
