import typing
import uuid
from datetime import datetime
from typing import Optional

import pydantic

from .fields import optional_name_line, user_name
from .mixins import SoftDeleteMixin, TimestampMixin


class Login(pydantic.BaseModel):
    username: user_name
    password: pydantic.SecretStr


class UserModel(SoftDeleteMixin):
    id: str
    email: pydantic.EmailStr
    email_confirmed_at: Optional[datetime]
    password: pydantic.SecretStr
    display_name: optional_name_line
    admin_level: int

    characters: dict[uuid.UUID, typing.Any] = pydantic.Field(
        default_factory=dict, exclude=True
    )  # Placeholder for CharacterModel list
    sessions: dict[uuid.UUID, typing.Any] = pydantic.Field(
        default_factory=dict, exclude=True
    )  # Placeholder for SessionModel dict
