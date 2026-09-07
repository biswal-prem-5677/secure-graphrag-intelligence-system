"""
Authentication API endpoints: login, current user info, and user registration.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from app.core.logging import get_logger
from app.models.user import User, UserRole, user_store
from app.schemas.schemas import LoginRequest, LoginResponse
from app.security.auth import create_access_token, get_current_user, hash_password, require_admin, verify_password
from app.security.rate_limiter import RateLimiter, check_rate_limit

logger = get_logger("api_auth")
router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
auth_limiter = RateLimiter(max_requests=20, window_seconds=60)


@router.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest, request: Request) -> LoginResponse:
    """Authenticate user with username and password, return JWT token."""
    check_rate_limit(request, auth_limiter, username=req.username)
    user = user_store.get_user(req.username)
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    token = create_access_token({"sub": user.username, "role": user.role.value})
    return LoginResponse(
        access_token=token,
        token_type="Bearer",
        username=user.username,
        role=user.role.value,
    )


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "role": current_user.role.value,
        "disabled": current_user.disabled,
    }


@router.post("/register")
async def register_user(
    req: LoginRequest,
    current_user: User = Depends(require_admin),
):
    """Admin-only endpoint to register new users."""
    if user_store.user_exists(req.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
    user = User(
        username=req.username,
        role=UserRole.analyst,
        hashed_password=hash_password(req.password),
    )
    user_store.add_user(user)
    return {"message": f"User {req.username} created successfully"}
