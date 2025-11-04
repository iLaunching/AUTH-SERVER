"""
Minimal Authentication API Server
Simple, focused API for user authentication only.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Dict
import os

# In-memory user storage (temporary - will move to DB later)
users_db: Dict[str, dict] = {}

# Pydantic models
class CheckEmailRequest(BaseModel):
    email: EmailStr

class CheckEmailResponse(BaseModel):
    exists: bool
    message: str

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    name: str = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    user: dict
    message: str

# Create FastAPI app
app = FastAPI(
    title="Authentication API",
    description="Minimal authentication service",
    version="1.0.0"
)

# CORS - allow all origins for now
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Authentication API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "auth": {
                "check_email": "POST /api/v1/auth/check-email",
                "signup": "POST /api/v1/auth/signup",
                "login": "POST /api/v1/auth/login"
            }
        }
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "auth-api",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "users_count": len(users_db)
    }

@app.post("/api/v1/auth/check-email", response_model=CheckEmailResponse)
async def check_email(request: CheckEmailRequest):
    """Check if email exists in system"""
    email = request.email.lower()
    exists = email in users_db
    
    if exists:
        return CheckEmailResponse(
            exists=True,
            message="Welcome back! Please enter your password to login."
        )
    else:
        return CheckEmailResponse(
            exists=False,
            message="Welcome! Let's create your account."
        )

@app.post("/api/v1/auth/signup", response_model=AuthResponse)
async def signup(request: SignupRequest):
    """Create new user account"""
    email = request.email.lower()
    
    # Check if user already exists
    if email in users_db:
        raise HTTPException(
            status_code=400,
            detail="Email already registered. Please login instead."
        )
    
    # Basic password validation
    if len(request.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long"
        )
    
    # Create user (storing plain password for now - will hash later)
    user_data = {
        "email": email,
        "name": request.name or email.split("@")[0],
        "password": request.password,  # TODO: Hash this
        "created_at": datetime.utcnow().isoformat()
    }
    
    users_db[email] = user_data
    
    # Return user without password
    return AuthResponse(
        user={
            "email": user_data["email"],
            "name": user_data["name"],
            "created_at": user_data["created_at"]
        },
        message="Account created successfully!"
    )

@app.post("/api/v1/auth/login", response_model=AuthResponse)
async def login(request: LoginRequest):
    """Login existing user"""
    email = request.email.lower()
    
    # Check if user exists
    if email not in users_db:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )
    
    user = users_db[email]
    
    # Check password (plain text for now - will add hashing later)
    if user["password"] != request.password:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )
    
    # Return user without password
    return AuthResponse(
        user={
            "email": user["email"],
            "name": user["name"],
            "created_at": user["created_at"]
        },
        message="Login successful!"
    )

