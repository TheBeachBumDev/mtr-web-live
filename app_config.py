"""Process-wide config read once at import (set APP_ROLE in main_*.py before importing main)."""
import os

APP_ROLE = (os.getenv("APP_ROLE", "core") or "core").strip().lower()
