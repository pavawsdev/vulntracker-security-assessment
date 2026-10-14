from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(200), nullable=False)
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("ScanResult", back_populates="owner")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    severity = Column(String(20), default="medium")   # critical | high | medium | low
    status = Column(String(20), default="open")        # open | in_progress | resolved
    cve_id = Column(String(30), nullable=True)
    affected_component = Column(String(200), nullable=False)
    remediation_notes = Column(Text, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="scans")


# A time-limited, optionally password-protected public link to one scan
class ShareLink(Base):
    __tablename__ = "share_links"

    id = Column(Integer, primary_key=True, index=True)
    # SHA-256 of the token, never the token itself, so a DB leak yields no working links
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    # The scan being shared; links are removed when the scan is deleted
    scan_id = Column(Integer, ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False)
    # Who created the link, for audit
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    # bcrypt hash of the optional link password; NULL means no password
    password_hash = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    # Set by the server at creation; checked on every access
    expires_at = Column(DateTime, nullable=False)

    scan = relationship("ScanResult")
