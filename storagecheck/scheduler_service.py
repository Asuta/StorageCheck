from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from .db import Database


class SchedulerService:
    def __init__(self, db: Database, trigger_scan) -> None:
        self.db = db
        self.trigger_scan = trigger_scan
        self.timezone = datetime.now().astimezone().tzinfo
        self.scheduler = BackgroundScheduler(timezone=self.timezone)

    def start(self) -> None:
        if not self.scheduler.running:
            self.scheduler.start()

    def shutdown(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

    def sync_jobs(self) -> None:
        active_job_ids: set[str] = set()
        for target in self.db.list_targets():
            job_id = self._job_id(int(target["id"]))
            trigger = self._build_trigger(target)
            if trigger is None:
                job = self.scheduler.get_job(job_id)
                if job is not None:
                    self.scheduler.remove_job(job_id)
                continue
            active_job_ids.add(job_id)
            self.scheduler.add_job(
                self.trigger_scan,
                trigger=trigger,
                id=job_id,
                args=[int(target["id"])],
                replace_existing=True,
                coalesce=True,
                max_instances=1,
                misfire_grace_time=600,
            )

        existing_ids = {job.id for job in self.scheduler.get_jobs()}
        for job_id in existing_ids - active_job_ids:
            if job_id.startswith("target-"):
                self.scheduler.remove_job(job_id)

    def next_run_at(self, target_id: int) -> str | None:
        job = self.scheduler.get_job(self._job_id(target_id))
        if job is None or job.next_run_time is None:
            return None
        return job.next_run_time.isoformat()

    def _build_trigger(self, target: dict[str, Any]):
        if not target.get("enabled", True):
            return None
        schedule_type = target["schedule_type"]
        if schedule_type == "manual":
            return None
        if schedule_type == "hourly":
            interval_hours = int(target.get("interval_hours") or 1)
            start_date = datetime.now(tz=self.timezone) + timedelta(hours=interval_hours)
            return IntervalTrigger(hours=interval_hours, start_date=start_date, timezone=self.timezone)
        if schedule_type == "daily":
            raw_time = target.get("daily_time") or "09:00"
            hour_text, minute_text = raw_time.split(":", maxsplit=1)
            return CronTrigger(
                hour=int(hour_text),
                minute=int(minute_text),
                timezone=self.timezone,
            )
        return None

    @staticmethod
    def _job_id(target_id: int) -> str:
        return f"target-{target_id}"
