from fastapi import HTTPException, Request


def require_admin(request: Request) -> None:
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin only")


def require_login(request: Request) -> None:
    if int(getattr(request.state, "user_id", 0) or 0) <= 0:
        raise HTTPException(status_code=401, detail="Login required")
