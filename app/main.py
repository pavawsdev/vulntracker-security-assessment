import hashlib
import logging
import secrets
import traceback
from datetime import datetime, timedelta
from typing import List, Optional

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

import models
from auth import create_access_token, get_current_user, get_password_hash, verify_password
from config import NOTIFY_SERVICE_URL, PUBLIC_BASE_URL, SHARE_LINK_TTL_HOURS
from database import engine, get_db, search_scans_by_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnTracker API",
    description="Vulnerability tracking and management REST API",
    version="1.0.0",
)


@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s: %s", request.url, exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),
            "type": type(exc).__name__,
            "traceback": traceback.format_exc(),
            "path": str(request.url),
        },
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cve_id: Optional[str] = None
    affected_component: str
    remediation_notes: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    remediation_notes: Optional[str] = None


class ScanOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True


# Request body for creating a share link; the password is optional
class ShareCreate(BaseModel):
    # Minimum length keeps link passwords from being trivially guessable
    password: Optional[str] = Field(default=None, min_length=8)

    @field_validator("password")
    @classmethod
    def password_fits_bcrypt(cls, v: Optional[str]) -> Optional[str]:
        # bcrypt ignores bytes past 72, so reject longer passwords instead of silently truncating
        if v is not None and len(v.encode("utf-8")) > 72:
            raise ValueError("password must be at most 72 bytes")
        return v


# Response for a new share link; expires_at tells the sharer when it stops working
class ShareOut(BaseModel):
    share_url: str
    expires_at: datetime


# What external recipients see: no id, owner_id or internal remediation_notes
class SharedScanOut(BaseModel):
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    created_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fire_notify(event: str, payload: dict) -> None:
    try:
        httpx.post(
            f"{NOTIFY_SERVICE_URL}/notify",
            json={"event": event, "payload": payload},
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("Notification service unreachable: %s", exc)


# Tokens are 256-bit random values, so plain SHA-256 is enough (unlike human passwords, which need bcrypt)
def _hash_share_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    logger.info("Login attempt — username: %s password: %s", payload.username, payload.password)
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning(
            "Failed login — username: '%s' password: '%s'",
            payload.username,
            payload.password,
        )
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if payload.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical | high | medium | low")
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {
        "id": scan.id,
        "title": scan.title,
        "severity": scan.severity,
        "owner": current_user.username,
    })
    return scan


@app.get("/scans/search")
def search_scans(
    q: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not q or len(q) < 2:
        raise HTTPException(status_code=400, detail="Search query must be at least 2 characters")
    results = search_scans_by_query(db, q)
    return {"results": results, "count": len(results)}


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(models.ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if payload.status is not None:
        if payload.status not in ("open", "in_progress", "resolved"):
            raise HTTPException(status_code=400, detail="status must be open | in_progress | resolved")
        scan.status = payload.status
    if payload.remediation_notes is not None:
        scan.remediation_notes = payload.remediation_notes
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.updated", {
        "id": scan.id,
        "title": scan.title,
        "status": scan.status,
        "owner": current_user.username,
    })
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


# ---------------------------------------------------------------------------
# Shared report links
# ---------------------------------------------------------------------------

@app.post("/scans/{scan_id}/share", response_model=ShareOut, status_code=201)
def create_share_link(
    scan_id: int,
    payload: Optional[ShareCreate] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # Only the scan's owner can share it; other users get 404 so the scan's existence isn't revealed
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # 32 random bytes from the OS CSPRNG: unguessable, URL-safe token
    token = secrets.token_urlsafe(32)
    password = payload.password if payload else None
    link = models.ShareLink(
        token_hash=_hash_share_token(token),
        scan_id=scan.id,
        created_by=current_user.id,
        # Optional password is stored as a bcrypt hash, same as user passwords
        password_hash=get_password_hash(password) if password else None,
        # Expiry is fixed server-side; the client cannot choose or extend it
        expires_at=datetime.utcnow() + timedelta(hours=SHARE_LINK_TTL_HOURS),
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    # Audit log records IDs only, never the token or password
    logger.info("Share link %s created for scan %s by user %s", link.id, scan.id, current_user.id)
    return {"share_url": f"{PUBLIC_BASE_URL}/share/{token}", "expires_at": link.expires_at}


@app.get("/share/{token}", response_model=SharedScanOut)
def get_shared_scan(
    token: str,
    response: Response,
    password: Optional[str] = None,
    db: Session = Depends(get_db),
):
    # Look up by hash, since only hashes are stored
    link = db.query(models.ShareLink).filter(
        models.ShareLink.token_hash == _hash_share_token(token),
    ).first()
    # Unknown, expired and deleted-scan links all return the same 404, so nothing leaks about which tokens existed
    if not link or link.expires_at <= datetime.utcnow() or link.scan is None:
        raise HTTPException(status_code=404, detail="Share link not found or expired")
    # Missing or wrong password gets 401; only a holder of the secret token can reach this check
    if link.password_hash and not (password and verify_password(password, link.password_hash)):
        raise HTTPException(status_code=401, detail="A valid password is required for this link")

    # Don't let browsers/proxies cache the report, and don't leak the token via the Referer header
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    # response_model=SharedScanOut strips internal fields before returning
    return link.scan


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}
