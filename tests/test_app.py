import jwt
import pytest
from collections.abc import Generator
from fastapi import status
from fastapi.encoders import jsonable_encoder
from fastapi.testclient import TestClient
from pydantic import UUID4
from sqlmodel import Session, create_engine
from sqlmodel.pool import StaticPool

from app.main import (
    app,
    _create_db_and_tables,
    _get_session,
    _get_settings,
    _get_user,
    Blob,
    JWTSub,
    Settings,
    Token,
    User,
    UserCreate,
    UserGet,
)


@pytest.fixture(scope="module")
def settings() -> Settings:
    settings = _get_settings()
    settings.db_url = "sqlite://"
    return settings


@pytest.fixture(scope="module")
def session(settings: Settings) -> Generator[Session]:
    engine = create_engine(
        settings.db_url, connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    _create_db_and_tables(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(scope="module")
def client(session: Session) -> Generator[TestClient]:
    def _get_session_override():
        return session

    app.dependency_overrides[_get_session] = _get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture(scope="module")
def user1(client: TestClient, session: Session) -> tuple[User, Token, str]:
    username, password = "fish", "password"
    user_create = UserCreate(username=username, password=password)
    response = client.post("/user", json=jsonable_encoder(user_create))
    token = Token(**response.json())
    user = _get_user(user_create.username, session)
    assert user is not None
    return user, token, password


@pytest.fixture(scope="module")
def user2(client: TestClient, session: Session) -> tuple[User, Token, str]:
    username, password = "sushi", "tuna"
    user_create = UserCreate(username=username, password=password)
    response = client.post("/user", json=jsonable_encoder(user_create))
    token = Token(**response.json())
    user = _get_user(user_create.username, session)
    assert user is not None
    return user, token, password


def _build_auth_header(token: Token) -> dict[str, str]:
    header = {"Authorization": f"Bearer {token.access_token}"}
    return header


@pytest.mark.parametrize(
    "sub, want",
    [
        (
            JWTSub(
                username="username",
                blob_id=UUID4("e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7"),
            ),
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
                blob_id=UUID4("e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7"),
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
        ("username:<username> blob_id:not_a_uuid", None, ValueError),
    ],
)
def test_jwt_sub_from_str(sub_string: str, want: JWTSub | None, exc: Exception | None):
    if exc is None:
        assert JWTSub.from_str(sub_string) == want
        return
    with pytest.raises(exc):
        JWTSub.from_str(sub_string)


def test_post_token_non_existent_user(client):
    form_data = {"username": "username", "password": "password"}
    response = client.post("/token", data=form_data)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_post_token(
    user1: tuple[User, Token, str], client: TestClient, settings: Settings
):
    user, _, password = user1
    form_data = {"username": user.username, "password": password}
    response = client.post("/token", data=form_data)
    assert response.status_code == status.HTTP_200_OK
    token = Token(**response.json())
    assert token.token_type == "bearer"
    jwt_payload = jwt.decode(
        token.access_token,
        settings.secret_key,
        algorithms=[settings.jwt_signing_algorithm],
    )
    assert jwt_payload.get("sub") is not None
    jwt_sub = JWTSub.from_str(jwt_payload.get("sub"))
    assert jwt_sub.username == user.username
    assert jwt_sub.blob_id == user.blob_id


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


def test_post_user_already_exists(user1: tuple[User, Token, str], client: TestClient):
    user, _, password = user1
    payload = jsonable_encoder(UserCreate(username=user.username, password=password))
    response = client.post("/user", json=payload)
    assert response.status_code == status.HTTP_409_CONFLICT


def test_get_user_without_auth(client):
    response = client.get("/user")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_user(user1: tuple[User, Token, str], client: TestClient):
    user, token, _ = user1
    response = client.get("/user", headers=_build_auth_header(token))
    assert response.status_code == status.HTTP_200_OK
    user_get = UserGet(**response.json())
    assert user_get.username == user.username
    assert user_get.blob_id == user.blob_id


def test_get_blob_without_auth(client):
    response = client.get("/blob/e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_blob_does_not_exist(user1: tuple[User, Token, str], client: TestClient):
    user, token, _ = user1
    response = client.get(
        "/blob/e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7", headers=_build_auth_header(token)
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_blob_owned_by_another_user(
    user1: tuple[User, Token, str], user2: tuple[User, Token, str], client: TestClient
):
    _, user1_token, _ = user1
    _user2, _, _ = user2
    response = client.get(
        f"/blob/{_user2.blob_id}", headers=_build_auth_header(user1_token)
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_blob(user1: tuple[User, Token, str], client: TestClient):
    user, token, _ = user1
    response = client.get(f"/blob/{user.blob_id}", headers=_build_auth_header(token))
    assert response.status_code == status.HTTP_200_OK


def test_put_blob_without_auth(client):
    payload = jsonable_encoder(
        Blob(blob_id="e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7", blob=b"i'm a blob")
    )
    response = client.put("/blob/e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7", json=payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_put_blob_does_not_exist(user1: tuple[User, Token, str], client: TestClient):
    user, token, _ = user1
    blob = Blob(blob_id=UUID4("e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7"), blob=b"blob")
    response = client.put(
        f"/blob/{blob.blob_id}",
        json=jsonable_encoder(blob),
        headers=_build_auth_header(token),
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_put_blob_owned_by_another_user(
    user1: tuple[User, Token, str], user2: tuple[User, Token, str], client: TestClient
):
    _, user1_token, _ = user1
    _user2, _, _ = user2
    user2_blob = Blob(blob_id=_user2.blob_id, blob=_user2.blob)
    response = client.put(
        f"/blob/{user2_blob.blob_id}",
        json=jsonable_encoder(user2_blob),
        headers=_build_auth_header(user1_token),
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_put_blob(user1: tuple[User, Token, str], client: TestClient):
    user, token, _ = user1
    blob = Blob(blob_id=user.blob_id, blob=b"this is (probably) a new blob")
    response = client.put(
        f"/blob/{user.blob_id}",
        json=jsonable_encoder(blob),
        headers=_build_auth_header(token),
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT
    response = client.get(f"/blob/{user.blob_id}", headers=_build_auth_header(token))
    got_blob = Blob(**response.json())
    assert got_blob.blob_id == blob.blob_id
    assert got_blob.blob == blob.blob
