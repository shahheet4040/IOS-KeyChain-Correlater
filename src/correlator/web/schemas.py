"""
Pydantic Request & Response Data Contracts for Web Application
==============================================================
Provides structured, type-checked schemas for all REST API endpoints.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CaseCreateRequest(BaseModel):
    case_name: str = Field(..., description="Name of the case (e.g. Operation CyberShield)")
    case_number: str = Field(..., description="Official case number (e.g. FSL/2026/089)")
    examiner: str = Field(..., description="Name and title of Scientific Officer / Examiner")
    description: Optional[str] = Field("", description="Optional details or scope of the investigation")


class CaseSummary(BaseModel):
    case_id: str
    case_name: str
    case_number: str
    examiner: str
    status: str
    created_at: str
    device_count: int


class DeviceAddRequest(BaseModel):
    device_name: str = Field(..., description="Label for device (e.g. Suspect iPhone 14)")
    device_model: str = Field(..., description="Model identifier (e.g. iPhone14,7)")
    os_version: str = Field(..., description="iOS version (e.g. 16.5)")
    serial_number: str = Field(..., description="Serial number or UDID")
    source_type: str = Field("cellebrite", description="cellebrite, graykey, itunes, live_usb, or manual")
    source_path: Optional[str] = Field("", description="Path to extraction folder if already on disk")


class RunAnalysisRequest(BaseModel):
    extraction_path: str = Field(..., description="Path to iOS extraction root folder")
    keychain_path: str = Field(..., description="Path to keychain file (plist, json, xml, csv)")
    out_dir: Optional[str] = Field(None, description="Output directory for reports and decrypted exports")


class IngestDumpRequest(BaseModel):
    dump_path: str = Field(..., description="Path to raw Cellebrite, GrayKey, or iTunes dump directory")
    out_dir: Optional[str] = Field(None, description="Output directory for normalized data")
    auto_analyze: bool = Field(True, description="Whether to automatically run correlation and decryption")


class SearchRequest(BaseModel):
    directory: str = Field(..., description="Directory containing decrypted SQLite databases")
    keyword: str = Field(..., description="Keyword, phone number, address, or pattern to search")
    case_insensitive: bool = Field(True, description="Case insensitive search")
    max_results: int = Field(1000, description="Max hit count limit")


class SearchHitResponse(BaseModel):
    db_path: str
    db_name: str
    table_name: str
    column_name: str
    matched_value: str
    match_context: str
    row_data: Dict[str, Any]


class PairingDeviceCheck(BaseModel):
    udid: str = Field(..., description="UDID of target device")


class DeviceTriageRequest(BaseModel):
    udid: str = Field(..., description="UDID of connected device to triage")


class AfcPullRequest(BaseModel):
    udid: Optional[str] = Field(None, description="Target device UDID (optional if single device)")
    output_dir: Optional[str] = Field(None, description="Directory to save extracted media")


class CrackBackupRequest(BaseModel):
    manifest_path: str = Field(..., description="Path to Manifest.plist of encrypted iOS backup")
    wordlist_path: Optional[str] = Field(None, description="Path to candidate password dictionary")
    candidate_passwords: Optional[List[str]] = Field(None, description="Direct list of password strings to test")


class TimelineRequest(BaseModel):
    directory: Optional[str] = Field(None, description="Directory containing decrypted databases")
    max_records: int = Field(5000, description="Maximum number of chronological events")


class GeospatialRequest(BaseModel):
    directory: Optional[str] = Field(None, description="Directory containing seized images/AFC media")


class WatchlistScanRequest(BaseModel):
    directory: Optional[str] = Field(None, description="Directory containing decrypted SQLite databases")
    custom_keywords: Optional[List[str]] = Field(None, description="Additional case-specific watch terms")


