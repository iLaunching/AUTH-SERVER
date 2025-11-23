"""
Data models and Pydantic schemas for the API server.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, validator
import uuid

class AnalysisType(str, Enum):
    """Types of analysis that can be performed"""
    FULL_ANALYSIS = "full_analysis"
    COMPETITOR_ANALYSIS = "competitor_analysis"
    MARKET_ANALYSIS = "market_analysis"
    SOCIAL_ANALYSIS = "social_analysis"
    CONTENT_ANALYSIS = "content_analysis"

class JobStatusEnum(str, Enum):
    """Job status enumeration"""
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class AnalysisRequest(BaseModel):
    """Request model for starting an analysis"""
    company_name: str = Field(..., min_length=1, max_length=255, description="Name of the company to analyze")
    industry: Optional[str] = Field(None, max_length=100, description="Industry sector")
    analysis_type: AnalysisType = Field(AnalysisType.FULL_ANALYSIS, description="Type of analysis to perform")
    additional_context: Optional[str] = Field(None, max_length=1000, description="Additional context or requirements")
    priority: Optional[int] = Field(1, ge=1, le=5, description="Priority level (1=highest, 5=lowest)")
    
    @validator('company_name')
    def validate_company_name(cls, v):
        if not v or v.strip() == "":
            raise ValueError('Company name cannot be empty')
        return v.strip()
    
    @validator('industry')
    def validate_industry(cls, v):
        if v:
            return v.strip().lower()
        return v

class AnalysisResponse(BaseModel):
    """Response model for analysis requests"""
    job_id: str = Field(..., description="Unique job identifier")
    status: JobStatusEnum = Field(..., description="Current job status")
    message: str = Field(..., description="Human-readable status message")
    websocket_url: str = Field(..., description="WebSocket URL for real-time updates")
    created_at: datetime = Field(..., description="Job creation timestamp")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion time")

class JobStatus(BaseModel):
    """Model for job status information"""
    job_id: str
    status: JobStatusEnum
    progress: int = Field(0, ge=0, le=100, description="Progress percentage")
    current_stage: Optional[str] = Field(None, description="Current processing stage")
    message: Optional[str] = Field(None, description="Status message")
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    results_preview: Optional[Dict[str, Any]] = None

class StreamMessage(BaseModel):
    """Model for WebSocket streaming messages"""
    type: str = Field(..., description="Message type")
    job_id: Optional[str] = Field(None, description="Associated job ID")
    stage: Optional[str] = Field(None, description="Processing stage")
    content: Optional[str] = Field(None, description="Content to stream")
    progress: Optional[int] = Field(None, ge=0, le=100, description="Progress percentage")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class AnalysisResult(BaseModel):
    """Model for analysis results"""
    job_id: str
    worker_type: str
    result_data: Dict[str, Any]
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    processing_time_ms: Optional[int] = Field(None, ge=0)
    data_sources: Optional[List[str]] = Field(None)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ErrorResponse(BaseModel):
    """Model for error responses"""
    error: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Error code")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: Optional[str] = Field(None, description="Request correlation ID")

class HealthStatus(BaseModel):
    """Model for health check responses"""
    status: str = Field(..., description="Overall health status")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    service: str = Field("api-server", description="Service name")
    version: str = Field("1.0.0", description="Service version")
    redis: Optional[str] = Field(None, description="Redis connection status")
    websocket_connections: int = Field(0, description="Active WebSocket connections")

# Session management
class SessionInfo(BaseModel):
    """Model for session information"""
    session_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    user_agent: Optional[str] = None
    active_jobs: List[str] = Field(default_factory=list)