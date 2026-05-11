import os

os.environ.setdefault("APP_ROLE", "stock_management")

from main import app  # noqa: E402,F401
