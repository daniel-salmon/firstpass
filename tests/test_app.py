from uuid import UUID

import jwt
import pytest
from fastapi import status
from fastapi.encoders import jsonable_encoder
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import (
    app,
    _get_settings,
    _get_user,
    Blob,
    JWTSub,
    Settings,
    Token,
    User,
    UserCreate,
)


@pytest.fixture(scope="module")
def settings() -> Settings:
    settings = _get_settings()
    return settings


@pytest.fixture(scope="module")
def client() -> TestClient:
    client = TestClient(app)
    return client


@pytest.fixture(scope="module")
def user1(client: TestClient) -> User:
    user_create = UserCreate(username="fish", password="password")
    _ = client.post("/user", json=jsonable_encoder(user_create))
    user = _get_user(user_create.username)
    assert user is not None
    return user


@pytest.mark.parametrize(
    "sub, want",
    [
        (
            JWTSub(username="username", blob_id="e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7"),
            "username:username blob_id:e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7",
        ),
    ],
)
def test_jwt_sub__str__(sub: JWTSub, want: str):
    assert str(sub) == want


@pytest.mark.parametrize(
    "sub_string, want, exc",
    [
        (
            "username:<username> blob_id:e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7",
            JWTSub(
                username="<username>",
                blob_id=UUID("e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7"),
            ),
            None,
        ),
        ("blob_id:e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7", None, AssertionError),
        ("username:<username>", None, AssertionError),
        (
            "username:<username> blob_id:not_a_uuid new_field:pizza",
            None,
            AssertionError,
        ),
        ("username:<username> blob_id:not_a_uuid", None, ValidationError),
    ],
)
def test_jwt_sub_from_str(sub_string: str, want: JWTSub | None, exc: Exception | None):
    if exc is None:
        assert JWTSub.from_str(sub_string) == want
        return
    with pytest.raises(exc):
        JWTSub.from_str(sub_string)


def test_root_without_auth(client):
    response = client.get("/")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_post_token_non_existent_user(client):
    form_data = {"username": "username", "password": "password"}
    response = client.post("/token", data=form_data)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.parametrize(
    "user_create", [UserCreate(username="username", password="password")]
)
def test_post_user(user_create: UserCreate, client: TestClient, settings: Settings):
    response = client.post("/user", json=jsonable_encoder(user_create))
    assert response.status_code == status.HTTP_201_CREATED
    token = Token(**response.json())
    assert token.token_type == "bearer"
    jwt_payload = jwt.decode(
        token.access_token,
        settings.secret_key,
        algorithms=[settings.jwt_signing_algorithm],
    )
    assert jwt_payload.get("sub") is not None
    jwt_sub = JWTSub.from_str(jwt_payload.get("sub"))
    assert jwt_sub.username == user_create.username
    assert jwt_sub.blob_id is not None


def test_post_user_already_exists(user1: User, client: TestClient):
    # NOTE: Have to use the plaintext password pulled from the user1 fixture
    # because the User object only keeps the hashed password
    payload = jsonable_encoder(UserCreate(username=user1.username, password="password"))
    response = client.post("/user", json=payload)
    assert response.status_code == status.HTTP_409_CONFLICT


def test_get_blob_without_auth(client):
    response = client.get("/e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_put_blob_without_auth(client):
    payload = jsonable_encoder(
        Blob(blob_id="e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7", blob=b"i'm a blob")
    )
    response = client.put("/e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7", json=payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
