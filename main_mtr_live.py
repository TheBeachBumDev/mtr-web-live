import os

os.environ.setdefault("APP_ROLE", "mtr_live")

from main import app  # noqa: E402,F401
