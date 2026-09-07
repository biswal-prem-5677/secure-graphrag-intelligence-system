"""
Authentication API endpoints: registration, login, logout, and current user info.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from app.core.logging import get_logger
from app.db.repository import ProfileRepository, SubscriptionRepository, UserRepository
from app.models.user import User, UserRole, user_store
from app.schemas.schemas import LoginRequest, LoginResponse, RegisterRequest, UserResponse
from app.security.auth import create_access_token, get_current_user, hash_password, require_admin, verify_password
from app.security.rate_limiter import RateLimiter, check_rate_limit

logger = get_logger("api_auth")
router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
auth_limiter = RateLimiter(max_requests=20, window_seconds=60)


@router.post("/register", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, request: Request) -> LoginResponse:
    """Public registration endpoint for new users.
    
    Creates a new user account, initializes a default profile and free subscription,
    and returns a JWT token for immediate authenticated session access.
    """
    check_rate_limit(request, auth_limiter, username=req.username)

    # Check for duplicate username
    if user_store.user_exists(req.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is already registered",
        )

    # Check for duplicate email if provided
    if req.email and UserRepository.get_by_email(req.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address is already registered",
        )

    # Hash password securely with bcrypt
    hashed_pw = hash_password(req.password)

    # Persist user in database
    db_user = UserRepository.create(
        username=req.username,
        hashed_password=hashed_pw,
        email=req.email,
        role=UserRole.analyst.value,
    )

    # Initialize default user profile & subscription tier
    ProfileRepository.get_or_create(
        user_id=db_user.username,
        display_name=req.username,
        email=req.email,
    )
    SubscriptionRepository.get_or_create(user_id=db_user.username)

    logger.info("user_registered_successfully", username=req.username)

    token = create_access_token({"sub": db_user.username, "role": db_user.role})
    return LoginResponse(
        access_token=token,
        token_type="Bearer",
        username=db_user.username,
        role=db_user.role,
    )


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
    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been disabled",
        )

    token = create_access_token({"sub": user.username, "role": user.role.value})
    return LoginResponse(
        access_token=token,
        token_type="Bearer",
        username=user.username,
        role=user.role.value,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)) -> UserResponse:
    """Return authenticated current user profile without sensitive fields."""
    db_user = UserRepository.get_by_username(current_user.username)
    return UserResponse(
        id=db_user.id if db_user else None,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role.value,
        disabled=current_user.disabled,
    )


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    """Acknowledge logout for the authenticated session."""
    logger.info("user_logged_out", username=current_user.username)
    return {"message": "Logged out successfully"}

