import os

os.environ.setdefault("APP_ROLE", "monitoring")

from main import app  # noqa: E402,F401
