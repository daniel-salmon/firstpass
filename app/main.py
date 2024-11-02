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
from pydantic.types import StringConstraints
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    secret_key: Annotated[str, StringConstraints(min_length=64, max_length=64)]
    jwt_signing_algorithm: str
    access_token_expire_minutes: timedelta
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
    blob_id: UUID = Field(default_factory=uuid4)
    blob: bytes | None = None


class User(UserBase, Blob):
    pass


class UserCreate(UserBase):
    pass


class UserGet(BaseModel):
    username: str
    blob_id: UUID


db: dict[str, User] = {}

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def _get_user(username: str) -> User | None:
    return db.get(username)


def _set_user(user: User) -> User:
    db[user.username] = user
    return user


def _update_user_blob(user: User, blob: Blob) -> None:
    user.blob = blob.blob


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
    user = _get_user(username)
    if user is None:
        raise credentials_exception
    return user


@app.post("/user")
async def create_user(
    new_user: UserCreate, settings: Annotated[Settings, Depends(get_settings)]
) -> Token:
    if _get_user(new_user.username) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )
    hashed_password = pwd_ctx.hash(new_user.password)
    user = _set_user(User(username=new_user.username, password=hashed_password))
    access_token = _create_access_token(
        data={"sub": f"username: {user.username} blob_id: {user.blob_id}"},
        settings=settings,
    )
    return Token(access_token=access_token, token_type="bearer")


def _create_access_token(
    *,
    data: dict,
    settings: Settings,
    expires_delta: timedelta | None = None,
):
    if expires_delta is None:
        expires_delta = settings.access_token_expire_minutes
    data = data.copy()
    exp = datetime.now(timezone.utc) + expires_delta
    data.update({"exp": exp})
    encoded_jwt = jwt.encode(
        data, settings.secret_key, algorithm=settings.jwt_signing_algorithm
    )
    return encoded_jwt


def _authenticate_user(username: str, password: str):
    user = _get_user(username)
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
    user = _authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = _create_access_token(
        data={"sub": f"username: {user.username} blob_id: {user.blob_id}"},
        settings=settings,
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/", status_code=status.HTTP_200_OK)
async def get_user(user: Annotated[User, Depends(_get_current_user)]) -> UserGet:
    return UserGet(username=user.username, blob_id=user.blob_id)


@app.get("/{blob_id}", status_code=status.HTTP_200_OK)
async def get_blob(
    blob_id: UUID, user: Annotated[User, Depends(_get_current_user)]
) -> Blob:
    if blob_id != user.blob_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Blob does not match User's blob",
            headers={"WWW-Authenticate": "Bearer"},
        )
    blob = Blob(blob_id=user.blob_id, blob=user.blob)
    return blob


@app.put("/{blob_id}", status_code=status.HTTP_204_NO_CONTENT)
async def put_blob(
    blob_id: UUID, blob: Blob, user: Annotated[User, Depends(_get_current_user)]
):
    if blob_id != user.blob_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Blob does not match User's blob",
            headers={"WWW-Authenticate": "Bearer"},
        )
    _update_user_blob(user, blob)
