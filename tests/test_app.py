import pytest

from fastapi import status
from fastapi.encoders import jsonable_encoder
from fastapi.testclient import TestClient

from app.main import app, Blob


@pytest.fixture(scope="session")
def client():
    client = TestClient(app)
    return client


def test_root_without_auth(client):
    response = client.get("/")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_blob_without_auth(client):
    response = client.get("/e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_put_blob_without_auth(client):
    payload = jsonable_encoder(
        Blob(blob_id="e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7", blob=b"i'm a blob")
    )
    response = client.put("/e9dae530-6f2a-4bd2-8bfc-6ea6a747f4c7", json=payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
