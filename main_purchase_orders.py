import os

os.environ["APP_ROLE"] = "purchase_orders"

from main import app  # noqa: E402,F401

