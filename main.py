"""
Minimal Authentication API Server
Simple, focused API for user authentication only.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import os

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
            "docs": "/docs"
        }
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "auth-api",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }
