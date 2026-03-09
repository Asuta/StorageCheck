from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, model_validator

from .db import Database
from .scheduler_service import SchedulerService
from .services import ScanAlreadyRunningError, ScanManager, ScanNotRunningError
from .utils import default_label_for_path, normalize_path
from . import __version__

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.getenv("STORAGECHECK_DB", DATA_DIR / "storagecheck.db"))

db = Database(DB_PATH)
scan_manager = ScanManager(db)
scheduler_service = SchedulerService(db, scan_manager.queue_scan)
templates = Jinja2Templates(directory=str(BASE_DIR / "storagecheck" / "templates"))


class TargetPayload(BaseModel):
    label: str | None = Field(default=None, max_length=120)
    root_path: str
    scan_mode: Literal["depth", "full"] = "depth"
    max_depth: int = Field(default=6, ge=1, le=20)
    schedule_type: Literal["manual", "hourly", "daily"] = "manual"
    interval_hours: int | None = Field(default=None, ge=1, le=168)
    daily_time: str | None = Field(default=None, pattern=r"^\d{2}:\d{2}$")
    enabled: bool = True

    @model_validator(mode="after")
    def validate_schedule(self) -> "TargetPayload":
        if self.schedule_type == "hourly" and self.interval_hours is None:
            self.interval_hours = 1
        if self.schedule_type != "hourly":
            self.interval_hours = None
        if self.schedule_type == "daily" and self.daily_time is None:
            self.daily_time = "09:00"
        if self.schedule_type != "daily":
            self.daily_time = None
        if self.scan_mode == "full":
            self.max_depth = 20
        return self


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.initialize()
    scheduler_service.start()
    scheduler_service.sync_jobs()
    yield
    scheduler_service.shutdown()
    scan_manager.shutdown()


app = FastAPI(title="StorageCheck", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "storagecheck" / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"app_title": "StorageCheck", "asset_version": __version__ + "-stale-delete-fix"},
    )


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/targets")
def list_targets() -> list[dict[str, object]]:
    return [_decorate_target(target) for target in db.list_targets()]


@app.post("/api/targets")
def create_target(payload: TargetPayload) -> dict[str, object]:
    target_data = _normalized_target_payload(payload)
    try:
        target = db.create_target(target_data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scheduler_service.sync_jobs()
    return _decorate_target(target)


@app.put("/api/targets/{target_id}")
def update_target(target_id: int, payload: TargetPayload) -> dict[str, object]:
    target_data = _normalized_target_payload(payload)
    try:
        target = db.update_target(target_id, target_data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found.")
    scheduler_service.sync_jobs()
    return _decorate_target(target)


@app.delete("/api/targets/{target_id}")
def delete_target(target_id: int) -> dict[str, object]:
    target = db.get_target(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found.")
    if scan_manager.is_scanning(target_id):
        raise HTTPException(status_code=409, detail="Cannot delete a target that is currently scanning.")
    deleted = db.delete_target(target_id)
    if deleted is None:
        raise HTTPException(status_code=404, detail="Target not found.")
    scheduler_service.sync_jobs()
    return {"status": "deleted", "target_id": target_id}


@app.post("/api/targets/{target_id}/scan")
def trigger_scan(target_id: int) -> dict[str, object]:
    if db.get_target(target_id) is None:
        raise HTTPException(status_code=404, detail="Target not found.")
    try:
        scan_manager.queue_scan(target_id)
    except ScanAlreadyRunningError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": "queued"}


@app.post("/api/targets/{target_id}/stop")
def stop_scan(target_id: int) -> dict[str, object]:
    if db.get_target(target_id) is None:
        raise HTTPException(status_code=404, detail="Target not found.")
    try:
        state = scan_manager.stop_scan(target_id)
    except ScanNotRunningError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": "stopping", "progress": state}


@app.get("/api/targets/{target_id}/scans")
def list_target_scans(target_id: int, limit: int = 12) -> list[dict[str, object]]:
    target = db.get_target(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found.")
    scans = db.list_scans(target_id, limit=min(max(limit, 1), 50))
    active_scan = scan_manager.get_active_state(target_id)
    if active_scan is None or active_scan.get("scan_id") is None:
        return scans

    matched = False
    for scan in scans:
        if scan["id"] != active_scan["scan_id"]:
            continue
        scan["progress"] = active_scan
        scan["engine"] = active_scan.get("engine") or scan.get("engine") or "recursive"
        scan["total_size_bytes"] = int(active_scan.get("scanned_size_bytes") or scan.get("total_size_bytes") or 0)
        scan["stored_node_count"] = int(active_scan.get("stored_node_count") or scan.get("stored_node_count") or 0)
        matched = True
        break

    if not matched:
        scans.insert(
            0,
            {
                "id": active_scan["scan_id"],
                "target_id": target_id,
                "root_path": target["root_path"],
                "mode": target["scan_mode"],
                "max_depth": None if target["scan_mode"] == "full" else target["max_depth"],
                "engine": active_scan.get("engine") or "recursive",
                "started_at": active_scan.get("started_at"),
                "finished_at": None,
                "status": active_scan.get("status") or "running",
                "total_size_bytes": int(active_scan.get("scanned_size_bytes") or 0),
                "stored_node_count": int(active_scan.get("stored_node_count") or 0),
                "error_message": active_scan.get("error_message"),
                "progress": active_scan,
            },
        )
    return scans[: min(max(limit, 1), 50)]


@app.get("/api/scans/{scan_id}/view")
def scan_view(scan_id: int, path: str | None = None) -> dict[str, object]:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    normalized_path = normalize_path(path) if path else None
    node = db.get_node(scan_id, normalized_path)
    if node is None:
        raise HTTPException(status_code=404, detail="Path not found in this scan.")
    children: list[dict[str, object]] = []
    if node["kind"] == "dir" and not node["is_truncated"]:
        children = db.list_children(scan_id, node["path"])
    history = db.get_path_history(scan_id, node["path"])
    breadcrumbs = db.get_breadcrumbs(scan_id, node["path"])
    return {
        "scan": scan,
        "node": node,
        "children": children,
        "breadcrumbs": breadcrumbs,
        "history": history,
    }


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int) -> dict[str, object]:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    active_scan = scan_manager.get_active_state(int(scan["target_id"]))
    if scan["status"] == "running" or (
        active_scan is not None and int(active_scan.get("scan_id") or 0) == scan_id
    ):
        raise HTTPException(status_code=409, detail="Cannot delete a scan that is currently running.")

    deleted = db.delete_scan(scan_id)
    if deleted is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    return {
        "status": "deleted",
        "scan_id": scan_id,
        "target_id": deleted["target_id"],
    }


def _normalized_target_payload(payload: TargetPayload) -> dict[str, object]:
    normalized_path = normalize_path(payload.root_path)
    if not os.path.exists(normalized_path):
        raise HTTPException(status_code=400, detail=f"Path does not exist: {normalized_path}")
    label = payload.label.strip() if payload.label else default_label_for_path(normalized_path)
    return {
        "label": label,
        "root_path": normalized_path,
        "scan_mode": payload.scan_mode,
        "max_depth": payload.max_depth,
        "schedule_type": payload.schedule_type,
        "interval_hours": payload.interval_hours,
        "daily_time": payload.daily_time,
        "enabled": payload.enabled,
    }


def _decorate_target(target: dict[str, object]) -> dict[str, object]:
    target_id = int(target["id"])
    active_scan = scan_manager.get_active_state(target_id)
    target["active_scan"] = active_scan
    target["is_scanning"] = active_scan is not None
    target["next_run_at"] = scheduler_service.next_run_at(target_id)
    return target
