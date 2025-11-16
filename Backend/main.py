"""
FastAPI Backend for Moleculum Lab
Implements user registration and login endpoints with JWT authentication.
"""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt

app = FastAPI(
    title="Moleculum Lab API",
    description="User registration and authentication API",
    version="1.0.0"
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

users_db = {}

user_id_counter = 1



class RegisterRequest(BaseModel):
    """Request model for user registration."""
    username: str
    email: EmailStr
    password: str


class RegisterResponse(BaseModel):
    """Response model for successful registration."""
    status: str
    message: str


class ErrorResponse(BaseModel):
    """Response model for error cases."""
    status: str
    message: str


class LoginRequest(BaseModel):
    """Request model for user login."""
    email: EmailStr
    password: str


class UserInfo(BaseModel):
    """User information model for login response."""
    id: int
    username: str


class LoginResponse(BaseModel):
    """Response model for successful login."""
    token: str
    user: UserInfo

def hash_password(password: str) -> str:
    """
    Hash a plain text password using bcrypt.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password string
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password.
    
    Args:
        plain_password: Plain text password to verify
        hashed_password: Hashed password to compare against
        
    Returns:
        True if passwords match, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Dictionary containing data to encode in the token (e.g., user email)
        expires_delta: Optional expiration time delta
        
    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.post("/api/register", response_model=RegisterResponse, status_code=status.HTTP_200_OK)
async def register_user(user_data: RegisterRequest):
    """
    Register a new user.
    
    Checks if the email already exists, then hashes the password
    and stores the user in the in-memory database.
    
    Args:
        user_data: Registration request containing username, email, and password
        
    Returns:
        Success response with status and message
        
    Raises:
        HTTPException: If email already exists (400 Bad Request)
    """
    global user_id_counter
    
    if user_data.email in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already exists"
        )
    
    hashed_password = hash_password(user_data.password)
    
    user_id = user_id_counter
    user_id_counter += 1
    
    users_db[user_data.email] = {
        "id": user_id,
        "username": user_data.username,
        "email": user_data.email,
        "hashed_password": hashed_password
    }
    
    return RegisterResponse(
        status="success",
        message="User created successfully"
    )


@app.post("/api/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login_user(credentials: LoginRequest):
    """
    Authenticate a user and return a JWT token.
    
    Verifies the email and password, then generates a JWT token
    if credentials are valid.
    
    Args:
        credentials: Login request containing email and password
        
    Returns:
        Login response with JWT token and user information
        
    Raises:
        HTTPException: If email doesn't exist or password is incorrect (400 Bad Request)
    """
    if credentials.email not in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or password"
        )
    
    user = users_db[credentials.email]
    
    if not verify_password(credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or password"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": credentials.email}, 
        expires_delta=access_token_expires
    )
    
    return LoginResponse(
        token=access_token,
        user=UserInfo(
            id=user["id"],
            username=user["username"]
        )
    )


@app.get("/")
async def root():
    """Root endpoint for health check."""
    return {"message": "Moleculum Lab API is running"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

