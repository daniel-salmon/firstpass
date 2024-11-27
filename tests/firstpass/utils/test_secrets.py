import pytest

from pydantic import SecretStr

from firstpass.utils import Password, Secrets


@pytest.mark.parametrize(
    "secrets",
    [
        Secrets(
            passwords={
                "password1": Password(username="fish", password=SecretStr("password"))
            }
        ),
        Secrets(
            passwords={
                "password1": Password(username="fish", password=SecretStr("password")),
                "password2": Password(
                    username="sticks",
                    password=SecretStr("password"),
                    label="https://pybit.es",
                    notes="lorem ipsum",
                ),
            }
        ),
    ],
)
def test_serialize_deserialize(secrets: Secrets) -> None:
    assert isinstance(secrets.serialize(), bytes)
    assert secrets.deserialize(secrets.serialize()) == secrets
