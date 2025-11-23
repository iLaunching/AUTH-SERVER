"""
Database configuration and connection management for Auth API
Phase 1: Basic database setup with graceful fallback
"""

import os
from typing import AsyncGenerator
import structlog
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker
)
from sqlalchemy.orm import declarative_base
import redis.asyncio as redis

logger = structlog.get_logger()

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL:
    # Convert postgres:// to postgresql+asyncpg:// for asyncpg driver
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
    elif DATABASE_URL.startswith("postgresql://") and "+asyncpg" not in DATABASE_URL:
        DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# SQLAlchemy setup - only create engine if DATABASE_URL is available
engine = None
async_session_maker = None

if DATABASE_URL:
    engine = create_async_engine(
        DATABASE_URL,
        echo=os.getenv("DATABASE_ECHO", "false").lower() == "true",
        pool_size=20,
        max_overflow=0,
        pool_pre_ping=True,
        pool_recycle=300
    )

    async_session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False
    )

Base = declarative_base()

# Redis setup
redis_client = None

async def init_redis():
    """Initialize Redis connection."""
    global redis_client
    try:
        redis_client = redis.from_url(
            REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True
        )
        # Test connection
        await redis_client.ping()
        logger.info("Redis connection established", url=REDIS_URL)
        return redis_client
    except Exception as e:
        logger.error("Failed to connect to Redis", error=str(e), url=REDIS_URL)
        # Don't raise - allow system to continue without Redis
        return None

async def get_redis():
    """Get Redis client."""
    global redis_client
    if redis_client is None:
        redis_client = await init_redis()
    return redis_client

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session.
    
    Yields:
        AsyncSession: Database session
    """
    if not async_session_maker:
        raise Exception("Database not initialized - async_session_maker is None")
        
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()

async def init_database():
    """Initialize database connection and create tables."""
    if not DATABASE_URL or not engine:
        logger.warning("DATABASE_URL not configured - running without database")
        return False
        
    try:
        # Test database connection
        async with engine.begin() as conn:
            # Phase 2: Import user models to register them with Base
            try:
                from models.user import User, Session, UserProfile, LoginAttempt
                logger.info("User models imported successfully")
            except ImportError as e:
                logger.error("Could not import user models", error=str(e))
                raise
            
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
            
        logger.info("Database connection established and tables created", url=DATABASE_URL[:50] + "...")
        return True
        
    except Exception as e:
        logger.error("Failed to connect to database", error=str(e), url=DATABASE_URL[:50] + "..." if DATABASE_URL else None)
        # Don't raise - allow system to continue without database
        return False

async def close_database():
    """Close database connections."""
    global redis_client
    
    try:
        if redis_client:
            await redis_client.close()
            logger.info("Redis connection closed")
    except Exception as e:
        logger.error("Error closing Redis connection", error=str(e))
    
    try:
        if engine:
            await engine.dispose()
            logger.info("Database connection closed")
    except Exception as e:
        logger.error("Error closing database connection", error=str(e))

# Health check functions
async def check_database_health() -> dict:
    """Check database connectivity."""
    if not async_session_maker:
        return {
            "status": "not_configured",
            "message": "Database not configured - missing DATABASE_URL"
        }
        
    try:
        async with async_session_maker() as session:
            from sqlalchemy import text
            result = await session.execute(text("SELECT 1"))
            return {
                "status": "healthy",
                "message": "Database connection successful"
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": f"Database connection failed: {str(e)}"
        }

async def check_redis_health() -> dict:
    """Check Redis connectivity."""
    try:
        if not redis_client:
            return {
                "status": "not_configured",
                "message": "Redis not configured"
            }
        await redis_client.ping()
        return {
            "status": "healthy",
            "message": "Redis connection successful"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": f"Redis connection failed: {str(e)}"
        }
