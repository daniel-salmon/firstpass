from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID, uuid4

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel, Field


SECRET_KEY = "a63aed4e83e489a77632a0c3e005808256cc6e0812102bf3d8c7a49fcaa461ad"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_ctx = CryptContext(schemes=["sha512_crypt"])

app = FastAPI()


class Token(BaseModel):
    access_token: str
    token_type: str


class NewUser(BaseModel):
    username: str
    password: str


class User(NewUser):
    id: UUID = Field(default_factory=uuid4)
    blob: bytes | None = None


db: dict[str, User] = {}


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = db.get(username)
    if user is None:
        raise credentials_exception
    return user


@app.post("/user")
async def new_user(new_user: NewUser) -> Token:
    if new_user.username in db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )
    hashed_password = pwd_ctx.hash(new_user.password)
    user = User(username=new_user.username, password=hashed_password)
    db[user.username] = user
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": f"{user.username}"},
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token, token_type="bearer")


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data = data.copy()
    exp = datetime.now(timezone.utc) + expires_delta
    data.update({"exp": exp})
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def authenticate_user(db: dict[str, User], username: str, password: str):
    user = db.get(username)
    if user is None:
        return None
    if not pwd_ctx.verify(password, user.password):
        return None
    return user


@app.post("/token")
async def token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": f"{user.username}"},
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/hello")
async def hello(user: Annotated[User, Depends(get_current_user)]):
    print(user)
    return user
