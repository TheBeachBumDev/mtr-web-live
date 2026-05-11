import os

os.environ.setdefault("APP_ROLE", "routers")

from main import app  # noqa: E402,F401
