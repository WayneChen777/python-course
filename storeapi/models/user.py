from typing import Optional

from pydantic import BaseModel


class User(BaseModel):
    id: Optional[int] = None
    # id: int | None = None
    email: str


class UserIn(User):
    password: str
