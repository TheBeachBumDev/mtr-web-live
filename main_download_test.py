import os

os.environ.setdefault("APP_ROLE", "download_test")

from main import app  # noqa: E402,F401
