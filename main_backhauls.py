import os

os.environ.setdefault("APP_ROLE", "backhauls")

from main import app  # noqa: E402,F401
