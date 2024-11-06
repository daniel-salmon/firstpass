import typer

from firstpass import __version__
from firstpass import config

app = typer.Typer()
app.add_typer(config.app, name="config")


@app.command()
def version():
    print(__version__)


@app.command()
def hello(name: str):
    print(name)
