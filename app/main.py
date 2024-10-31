from fastapi import FastAPI

from firstpass.secrets import Secrets

app = FastAPI()


@app.get("/")
async def root():
    return Secrets.deserialize(
        b'{"passwords": {"key": {"username": "dan", "password": "lame"}}}'
    )
