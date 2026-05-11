import os

os.environ.setdefault("APP_ROLE", "ipam")

from main import app  # noqa: E402,F401
