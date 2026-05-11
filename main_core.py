import os

os.environ.setdefault("APP_ROLE", "core")

from main import app  # noqa: E402,F401
