from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Annotated
from uuid import UUID, uuid4

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    secret_key: str
    jwt_signing_algorithm: str
    access_token_expire_minutes: int
    pwd_hash_scheme: str


@lru_cache
def get_settings():
    return Settings()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_ctx = CryptContext(schemes=[get_settings().pwd_hash_scheme])

app = FastAPI()


class Token(BaseModel):
    access_token: str
    token_type: str


class UserBase(BaseModel):
    username: str
    password: str


class Blob(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    blob: bytes | None = None


class User(UserBase, Blob):
    pass


class UserCreate(UserBase):
    pass


db: dict[str, User] = {}

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def _get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=[settings.jwt_signing_algorithm]
        )
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = db.get(username)
    if user is None:
        raise credentials_exception
    return user


@app.post("/user")
async def new_user(
    new_user: UserCreate, settings: Annotated[Settings, Depends(get_settings)]
) -> Token:
    if new_user.username in db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )
    hashed_password = pwd_ctx.hash(new_user.password)
    user = User(username=new_user.username, password=hashed_password)
    db[user.username] = user
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = _create_access_token(
        data={"sub": f"{user.username}"},
        settings=settings,
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token, token_type="bearer")


def _create_access_token(
    *,
    data: dict,
    settings: Annotated[Settings, Depends(get_settings)],
    expires_delta: timedelta | None = None,
):
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
    data = data.copy()
    exp = datetime.now(timezone.utc) + expires_delta
    data.update({"exp": exp})
    encoded_jwt = jwt.encode(
        data, settings.secret_key, algorithm=settings.jwt_signing_algorithm
    )
    return encoded_jwt


def _authenticate_user(db: dict[str, User], username: str, password: str):
    user = db.get(username)
    if user is None:
        return None
    if not pwd_ctx.verify(password, user.password):
        return None
    return user


@app.post("/token")
async def token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Annotated[Settings, Depends(get_settings)],
):
    user = _authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = _create_access_token(
        data={"sub": f"{user.username}"},
        settings=settings,
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/hello")
async def hello(user: Annotated[User, Depends(_get_current_user)]):
    print(user)
    return user
