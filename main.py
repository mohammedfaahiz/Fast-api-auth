"""FastAPI application providing JWT-based authentication and user endpoints."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Optional

from dotenv import load_dotenv
import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

users_file_path = Path("users.json")
if users_file_path.exists():
    with users_file_path.open("r", encoding="utf-8") as f:
        fake_users_db = json.load(f)
else:
    fake_users_db = {}


class Token(BaseModel):
    """Model representing a JWT token."""

    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Data extracted from a decoded JWT token."""

    username: Optional[str] = None


class User(BaseModel):
    """Public-facing user model."""

    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    """Internal user model with hashed password."""

    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify that the provided password matches the stored hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate a hashed version of a plain password."""
    return pwd_context.hash(password)


def get_user(db: dict, username: str) -> Optional[UserInDB]:
    """Retrieve a user from the database by username."""
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None


def authenticate_user(
    fake_db: dict, username: str, password: str
) -> Optional[UserInDB]:
    """Authenticate a user by username and password."""
    user = get_user(fake_db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token with optional expiration."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> UserInDB:
    """Retrieve the currently authenticated user from the JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError as exc:
        raise credentials_exception from exc

    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Ensure that the currently authenticated user is active."""
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """Generate an access token for valid login credentials."""
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    """Return the current authenticated user."""
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> list[dict]:
    """Return items that belong to the current authenticated user."""
    return [{"item_id": "Foo", "owner": current_user.username}]
