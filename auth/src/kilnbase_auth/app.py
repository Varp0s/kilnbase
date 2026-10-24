from fastapi import FastAPI

from .config import Config


def create_app(config: Config) -> FastAPI:
    app = FastAPI(title="Kilnbase Auth", docs_url=None, redoc_url=None)
    app.state.config = config

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    return app
