"""Single shared Jinja2 environment (filters, cache) for all HTML routes."""
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")
templates.env.auto_reload = True
templates.env.cache = {}


def _jinja_norm_path(p: str) -> str:
    x = (str(p) if p is not None else "").strip().rstrip("/")
    return x if x else "/"


templates.env.filters["norm_path"] = _jinja_norm_path
