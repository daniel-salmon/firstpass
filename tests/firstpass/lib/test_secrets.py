import pytest

from firstpass.lib.secrets import Password, Secrets


@pytest.mark.parametrize(
    "secrets",
    [
        Secrets(
            passwords={"password1": Password(username="fish", password="password")}
        ),
        Secrets(
            passwords={
                "password1": Password(username="fish", password="password"),
                "password2": Password(
                    username="sticks",
                    password="password",
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
