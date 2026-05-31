"""
DS1 Hunter - Hunts App Views
DigitalSecurity1 - "Hunt. Chain. Prove."
"""

import asyncio
import logging
import sys
import threading
import time as _time
from pathlib import Path
from urllib.parse import quote

from django.conf import settings

# Ensure ds1hunter/core is importable (mirrors tasks.py)
_CORE_ROOT = str(Path(__file__).resolve().parent.parent.parent.parent)
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)

from django.utils import timezone
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework.views import APIView

from .models import AuthConfig, Hunt, Vulnerability
from .serializers import (
    AuthConfigListSerializer,
    AuthConfigSerializer,
    HuntCreateSerializer,
    HuntDetailSerializer,
    HuntListSerializer,
    VulnerabilitySerializer,
    VulnerabilityUpdateSerializer,
)

logger = logging.getLogger("ds1hunter.views")

# ── Task imports - all guarded so a broken tasks.py never kills the whole app ─
try:
    from .tasks import run_hunt_task
    from .tasks import pause_hunt  as _task_pause
    from .tasks import resume_hunt as _task_resume
    from .tasks import stop_hunt   as _task_stop
    from .tasks import _LIVE, _HUNT_PAUSE_EVENTS
    logger.info("[Views] Task imports OK")
except ImportError as _ie:
    logger.error("[Views] FAILED to import from tasks: %s", _ie)
    run_hunt_task      = None
    _task_pause        = lambda *a, **kw: False
    _task_resume       = lambda *a, **kw: False
    _task_stop         = lambda *a, **kw: False
    _LIVE              = {}
    _HUNT_PAUSE_EVENTS = {}


# ─────────────────────────────────────────────────────────────────────────────
#  Dispatch helper
# ─────────────────────────────────────────────────────────────────────────────

def _dispatch_hunt(hunt_id: str) -> None:
    """
    Dispatch a hunt task.
      • Redis available   → Celery worker (.delay)
                           Falls back to thread if .delay() raises.
      • Redis unavailable → background daemon thread (dev mode)

    Every failure path marks the hunt FAILED in the DB so the user
    never sees a hunt permanently stuck in 'pending'.
    """
    hunt_id = str(hunt_id)
    logger.info("[Dispatch] Called for hunt %s", hunt_id)

    # ── Guard: tasks module failed to import ──────────────────────────────────
    if run_hunt_task is None:
        logger.error(
            "[Dispatch] run_hunt_task is None - tasks import failed. "
            "Hunt %s will be marked failed.", hunt_id
        )
        _mark_hunt_failed(hunt_id, "Task system failed to import - check server logs.")
        return

    try:
        if getattr(settings, "REDIS_AVAILABLE", False):
            # ── Celery mode ───────────────────────────────────────────────────
            logger.info("[Dispatch] Celery mode - sending task for hunt %s", hunt_id)
            try:
                result = run_hunt_task.delay(hunt_id)
                logger.info(
                    "[Dispatch] Celery task queued - task_id=%s hunt=%s",
                    result.id, hunt_id,
                )
            except Exception as celery_exc:
                logger.error(
                    "[Dispatch] Celery .delay() failed for hunt %s: %s "
                    "- falling back to thread mode.", hunt_id, celery_exc
                )
                _dispatch_as_thread(hunt_id)
        else:
            # ── Thread mode (dev / no Redis) ──────────────────────────────────
            _dispatch_as_thread(hunt_id)

    except Exception as exc:
        logger.exception(
            "[Dispatch] Unexpected error dispatching hunt %s: %s", hunt_id, exc
        )
        _mark_hunt_failed(hunt_id, f"Dispatch error: {exc}")


def _dispatch_as_thread(hunt_id: str) -> None:
    """
    Run the hunt task in a background daemon thread.
    The thread wrapper catches all exceptions and writes them to the DB
    so the hunt never silently stays 'pending'.
    """
    logger.info("[Dispatch] Thread mode for hunt %s", hunt_id)
    try:
        # Import the underlying Python function directly -
        # NOT the Celery @shared_task wrapper, to avoid binding issues.
        from .tasks import run_hunt_task as _raw_fn

        def _thread_target():
            try:
                logger.info("[Dispatch] Thread running - hunt %s", hunt_id)
                _raw_fn(hunt_id)
                logger.info("[Dispatch] Thread finished - hunt %s", hunt_id)
            except Exception as thread_exc:
                logger.exception(
                    "[Dispatch] Thread crashed for hunt %s: %s",
                    hunt_id, thread_exc,
                )
                _mark_hunt_failed(hunt_id, f"Worker thread crashed: {thread_exc}")

        t = threading.Thread(
            target=_thread_target,
            daemon=True,
            name=f"ds1-hunt-{hunt_id[:8]}",
        )
        t.start()
        logger.info(
            "[Dispatch] Thread launched - name=%s alive=%s",
            t.name, t.is_alive(),
        )
    except Exception as exc:
        logger.exception(
            "[Dispatch] Failed to start thread for hunt %s: %s", hunt_id, exc
        )
        _mark_hunt_failed(hunt_id, f"Thread launch failed: {exc}")


def _mark_hunt_failed(hunt_id: str, reason: str) -> None:
    """
    Best-effort: set hunt status to FAILED with an error message.
    Never raises - called from exception handlers.
    """
    try:
        hunt = Hunt.objects.get(id=hunt_id)
        if hunt.status not in (Hunt.Status.FAILED, Hunt.Status.COMPLETED):
            hunt.status        = Hunt.Status.FAILED
            hunt.error_message = reason
            hunt.completed_at  = timezone.now()
            hunt.save(update_fields=["status", "error_message", "completed_at"])
            logger.info("[Dispatch] Hunt %s marked FAILED: %s", hunt_id, reason)
    except Exception as db_exc:
        logger.error(
            "[Dispatch] Could not mark hunt %s failed: %s", hunt_id, db_exc
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Hunt ViewSet
# ─────────────────────────────────────────────────────────────────────────────

class HuntViewSet(viewsets.ModelViewSet):
    """
    CRUD + action endpoints for Hunt objects.

    list:      GET    /api/hunts/
    create:    POST   /api/hunts/
    retrieve:  GET    /api/hunts/{id}/
    cancel:    POST   /api/hunts/{id}/cancel/
    pause:     POST   /api/hunts/{id}/pause/
    resume:    POST   /api/hunts/{id}/resume/
    rerun:     POST   /api/hunts/{id}/rerun/
    vulns:     GET    /api/hunts/{id}/vulnerabilities/
    live_data: GET    /api/hunts/{id}/live_data/
    """

    permission_classes  = [IsAuthenticated]
    throttle_classes    = [UserRateThrottle]
    filter_backends     = [filters.SearchFilter, filters.OrderingFilter]
    search_fields       = ["target", "status"]
    ordering_fields     = ["created_at", "risk_score", "status"]
    ordering            = ["-created_at"]

    def get_queryset(self):
        return Hunt.objects.filter(
            created_by=self.request.user
        ).select_related("created_by")

    def get_serializer_class(self):
        if self.action == "create":
            return HuntCreateSerializer
        if self.action in ("retrieve", "vulnerabilities"):
            return HuntDetailSerializer
        return HuntListSerializer

    # ── Create ────────────────────────────────────────────────────────────────

    def create(self, request, *args, **kwargs):
        serializer = HuntCreateSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        hunt = serializer.save()
        logger.info(
            "[Views] Hunt %s created by %s - target=%s depth=%s",
            hunt.id, request.user, hunt.target, hunt.scan_depth,
        )
        _dispatch_hunt(str(hunt.id))
        return Response(
            HuntDetailSerializer(hunt, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )

    # ── Cancel ────────────────────────────────────────────────────────────────

    @action(detail=True, methods=["post"])
    def cancel(self, request, pk=None):
        """Stop a pending, running, or paused hunt."""
        hunt = self.get_object()

        if hunt.status not in (
            Hunt.Status.PENDING,
            Hunt.Status.RUNNING,
            Hunt.Status.PAUSED,
        ):
            return Response(
                {"detail": "Only pending, running, or paused hunts can be stopped."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        worker_signalled = _task_stop(str(hunt.id))
        logger.info(
            "[Views] cancel - hunt=%s worker_signalled=%s",
            hunt.id, worker_signalled,
        )

        hunt.status        = Hunt.Status.FAILED
        hunt.error_message = "Stopped by user."
        hunt.completed_at  = timezone.now()
        hunt.save(update_fields=["status", "error_message", "completed_at"])

        return Response({
            "detail":           "Hunt stopped.",
            "worker_signalled": worker_signalled,
        })

    # ── Pause ─────────────────────────────────────────────────────────────────

    @action(detail=True, methods=["post"])
    def pause(self, request, pk=None):
        """Pause a running hunt between phases."""
        hunt = self.get_object()

        if hunt.status != Hunt.Status.RUNNING:
            return Response(
                {"detail": "Only running hunts can be paused."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        worker_signalled = _task_pause(str(hunt.id))
        logger.info(
            "[Views] pause - hunt=%s worker_signalled=%s",
            hunt.id, worker_signalled,
        )

        hunt.status = Hunt.Status.PAUSED
        hunt.save(update_fields=["status"])

        return Response({
            "detail":           "Hunt paused.",
            "worker_signalled": worker_signalled,
            "note": (
                None if worker_signalled
                else "Worker not found - hunt may have already completed."
            ),
        })

    # ── Resume ────────────────────────────────────────────────────────────────

    @action(detail=True, methods=["post"])
    def resume(self, request, pk=None):
        """Resume a paused hunt."""
        hunt = self.get_object()

        if hunt.status != Hunt.Status.PAUSED:
            return Response(
                {"detail": "Only paused hunts can be resumed."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        worker_signalled = _task_resume(str(hunt.id))
        logger.info(
            "[Views] resume - hunt=%s worker_signalled=%s",
            hunt.id, worker_signalled,
        )

        hunt.status = Hunt.Status.RUNNING
        hunt.save(update_fields=["status"])

        return Response({
            "detail":           "Hunt resumed.",
            "worker_signalled": worker_signalled,
            "note": (
                None if worker_signalled
                else "Worker not found - hunt may have already completed."
            ),
        })

    # ── Rerun ─────────────────────────────────────────────────────────────────

    @action(detail=True, methods=["post"])
    def rerun(self, request, pk=None):
        """Re-queue a failed or completed hunt."""
        hunt = self.get_object()

        if hunt.status not in (Hunt.Status.FAILED, Hunt.Status.COMPLETED):
            return Response(
                {"detail": "Only failed or completed hunts can be re-queued."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Stop any lingering worker first
        _task_stop(str(hunt.id))

        hunt.status           = Hunt.Status.PENDING
        hunt.results          = {}
        hunt.risk_score       = None
        hunt.attack_chains    = []
        hunt.severity_summary = {}
        hunt.error_message    = ""
        hunt.started_at       = None
        hunt.completed_at     = None
        hunt.save()
        hunt.vulnerabilities.all().delete()

        logger.info("[Views] rerun - hunt=%s user=%s", hunt.id, request.user)
        _dispatch_hunt(str(hunt.id))
        return Response({"detail": "Hunt re-queued."})

    # ── Live data ─────────────────────────────────────────────────────────────

    @action(detail=True, methods=["get"])
    def live_data(self, request, pk=None):
        """
        Return in-process live state for a running/paused hunt.
        Polled by the frontend every 1.5 s as a reliable REST fallback
        alongside WebSocket delivery.
        """
        hunt    = self.get_object()
        hunt_id = str(hunt.id)

        # _LIVE and _HUNT_PAUSE_EVENTS imported at module top (with fallback)
        state   = _LIVE.get(hunt_id)
        pause_evt = _HUNT_PAUSE_EVENTS.get(hunt_id)
        is_paused = (pause_evt is not None) and (not pause_evt.is_set())

        # When _LIVE has no entry the task already finished/failed/stopped,
        # or the server was restarted while a hunt was running.
        if state is None:
            db_st = hunt.status

            if db_st in ("completed", "failed", "stopped"):
                phase_label = "complete" if db_st == "completed" else "failed"
                phase_msg   = {
                    "completed": "Hunt complete!",
                    "failed":    hunt.error_message or "Hunt failed.",
                    "stopped":   "Hunt stopped by user.",
                }.get(db_st, db_st)
                return Response({
                    "phase":         phase_label,
                    "message":       phase_msg,
                    "progress":      100 if db_st == "completed" else 0,
                    "is_paused":     False,
                    "db_status":     db_st,
                    "attacks":       [],
                    "live_attacks":  [],
                    "total_attacks": 0,
                    "metrics":       {"total_attacks": 0, "phase_attack_counts": {}},
                })

            if db_st == "running":
                # Worker is gone but DB still says running — server restarted or
                # the worker thread crashed without updating the DB.
                # Auto-heal: mark the hunt as failed so the UI can recover.
                logger.warning(
                    "[Views] live_data: hunt %s has no live state but DB=running "
                    "— auto-healing to failed (likely server restart).",
                    hunt_id,
                )
                try:
                    hunt.status        = Hunt.Status.FAILED
                    hunt.error_message = (
                        "Hunt worker was lost (server restart or crash). "
                        "Use Re-run to start a new scan."
                    )
                    hunt.completed_at  = timezone.now()
                    hunt.save(update_fields=["status", "error_message", "completed_at"])
                except Exception as _db_exc:
                    logger.error("[Views] Could not auto-heal hunt %s: %s", hunt_id, _db_exc)
                return Response({
                    "phase":         "failed",
                    "message":       "Hunt worker lost — server restarted. Use Re-run to continue.",
                    "progress":      0,
                    "is_paused":     False,
                    "db_status":     "failed",
                    "attacks":       [],
                    "live_attacks":  [],
                    "total_attacks": 0,
                    "metrics":       {"total_attacks": 0, "phase_attack_counts": {}},
                })

            # pending: worker not started yet
            return Response({
                "phase":         "starting",
                "message":       "Waiting for worker to start hunt...",
                "progress":      0,
                "is_paused":     False,
                "db_status":     db_st,
                "attacks":       [],
                "live_attacks":  [],
                "total_attacks": 0,
                "metrics":       {"total_attacks": 0, "phase_attack_counts": {}},
            })

        attacks  = list((state or {}).get("attacks",  []))
        findings = list((state or {}).get("findings", []))
        offset   = int(request.query_params.get("offset", 0))
        new_findings   = findings[offset:]
        finding_counts = (state or {}).get("finding_counts", {k: 0 for k in ("critical","high","medium","low","info")})
        # Send only the last 60 raw probe events to the frontend (enough for the
        # live probe feed display; sending all 1000+ every 1.5 s is wasteful).
        recent_attacks = attacks[-60:]
        return Response({
            "phase":           (state or {}).get("phase"),
            "message":         (state or {}).get("message"),
            "progress":        (state or {}).get("progress", 0),
            "is_paused":       is_paused,
            "db_status":       hunt.status,
            "attacks":         recent_attacks,  # last 60 raw probes → probe feed
            "live_attacks":    new_findings,    # confirmed findings → Attack Monitor table
            "total_attacks":   len(attacks),    # total probe count (for display)
            "total_findings":  len(findings),   # confirmed finding count
            "finding_counts":  finding_counts,
            "metrics": {
                "total_attacks":        len(attacks),
                "total_findings":       len(findings),
                "finding_counts":       finding_counts,
                "phase_attack_counts":  (state or {}).get("phase_attack_counts", {}),
            },
        })

    # ── Vulnerabilities ───────────────────────────────────────────────────────

    @action(detail=True, methods=["get"])
    def vulnerabilities(self, request, pk=None):
        """Return paginated vulnerabilities for a hunt."""
        hunt  = self.get_object()
        vulns = hunt.vulnerabilities.all()

        severity = request.query_params.get("severity")
        if severity:
            vulns = vulns.filter(severity=severity.lower())

        page = self.paginate_queryset(vulns)
        if page is not None:
            return self.get_paginated_response(
                VulnerabilitySerializer(page, many=True).data
            )
        return Response(VulnerabilitySerializer(vulns, many=True).data)


# ─────────────────────────────────────────────────────────────────────────────
#  Vulnerability update
# ─────────────────────────────────────────────────────────────────────────────

class VulnerabilityUpdateView(APIView):
    """PATCH /api/hunts/{hunt_id}/vulnerabilities/{vuln_id}/"""

    permission_classes = [IsAuthenticated]

    def patch(self, request, hunt_id, vuln_id):
        try:
            vuln = Vulnerability.objects.get(
                id=vuln_id,
                hunt__id=hunt_id,
                hunt__created_by=request.user,
            )
        except Vulnerability.DoesNotExist:
            return Response(
                {"detail": "Not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = VulnerabilityUpdateSerializer(
            vuln, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(VulnerabilitySerializer(vuln).data)


# ─────────────────────────────────────────────────────────────────────────────
#  Hunt finding verifier
# ─────────────────────────────────────────────────────────────────────────────

class HuntVerifyFindingView(APIView):
    """
    POST /api/hunts/{hunt_id}/verify-finding/

    Body: { "vuln_type": "sql_injection", "endpoint": "https://...", "method": "GET" }

    Runs a targeted confirmation probe on the finding and returns:
      { "confirmed": bool, "confidence": float, "evidence": {...}, "detail": str }
    """

    permission_classes = [IsAuthenticated]

    def post(self, request, hunt_id):
        try:
            hunt = Hunt.objects.get(id=hunt_id, created_by=request.user)
        except Hunt.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        vuln_type = (request.data.get("vuln_type") or "").strip()
        endpoint  = (request.data.get("endpoint")  or "").strip()
        method    = (request.data.get("method")    or "GET").strip().upper()

        if not vuln_type or not endpoint:
            return Response(
                {"detail": "vuln_type and endpoint are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Run targeted confirmation probe via the exploit proof engine
        import asyncio
        from core.modules.exploit_proof import ExploitProofEngine

        try:
            engine = ExploitProofEngine(target=hunt.target or endpoint)
            finding = {
                "type":     vuln_type,
                "endpoint": endpoint,
                "method":   method,
            }
            loop = asyncio.new_event_loop()
            try:
                proof = loop.run_until_complete(engine.prove(finding))
            finally:
                loop.close()

            confirmed  = bool(proof.get("confirmed", False))
            confidence = float(proof.get("confidence", 0.0))
            evidence   = proof.get("evidence", {})
            detail     = proof.get("detail") or ("Confirmed" if confirmed else "Not confirmed by re-probe")

            # Persist confirmation on DB record if one exists
            try:
                vuln_qs = hunt.vulnerabilities.filter(
                    vuln_type=vuln_type,
                    endpoint__icontains=endpoint.split("?")[0][:120],
                )
                if vuln_qs.exists() and confirmed:
                    vuln_qs.update(status="confirmed")
            except Exception:
                pass

            return Response({
                "confirmed":  confirmed,
                "confidence": round(confidence, 2),
                "evidence":   evidence,
                "detail":     detail,
            })

        except Exception as exc:
            return Response(
                {"detail": f"Verification error: {exc}", "confirmed": False, "confidence": 0.0},
                status=status.HTTP_200_OK,
            )


# ─────────────────────────────────────────────────────────────────────────────
#  GraphQL Scanner
# ─────────────────────────────────────────────────────────────────────────────

class GraphQLListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.graphql_scanner import list_sessions
        return Response({"sessions": list_sessions()})

    def post(self, request):
        from core.modules.graphql_scanner import create_session, start_session
        url = (request.data.get("url") or "").strip()
        if not url:
            return Response(
                {"detail": "url required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        hdrs       = request.data.get("headers", {})
        session_id = create_session(url=url, headers=hdrs)
        start_session(session_id)
        return Response({"session_id": session_id}, status=status.HTTP_201_CREATED)


class GraphQLDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.graphql_scanner import get_session
        s = get_session(session_id)
        if not s:
            return Response(
                {"detail": "Not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(s)


# ─────────────────────────────────────────────────────────────────────────────
#  Spider
# ─────────────────────────────────────────────────────────────────────────────

class SpiderListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.spider import list_sessions
        return Response({"sessions": list_sessions()})

    def post(self, request):
        from core.modules.spider import create_session, start_session
        url = (request.data.get("url") or "").strip()
        if not url:
            return Response(
                {"detail": "url required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        session_id = create_session(
            url=url,
            max_depth=min(int(request.data.get("max_depth", 3)), 10),
            max_urls=min(int(request.data.get("max_urls", 200)), 2000),
            probe_hidden=bool(request.data.get("probe_hidden", False)),
        )
        start_session(session_id)
        return Response({"session_id": session_id}, status=status.HTTP_201_CREATED)


class SpiderDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.spider import get_session
        s = get_session(session_id)
        if not s:
            return Response(
                {"detail": "Not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(s)

    def delete(self, request, session_id):
        from core.modules.spider import get_session, stop_session, delete_session
        s = get_session(session_id)
        if not s:
            return Response(
                {"detail": "Not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        if s.get("running") or s.get("probe_hidden_running"):
            stop_session(session_id)
            return Response({"detail": "Stop requested."})
        delete_session(session_id)
        return Response({"detail": "Session deleted."})


class SpiderClearView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        from core.modules.spider import clear_sessions
        n = clear_sessions()
        return Response({"cleared": n})


class SpiderExportView(APIView):
    """GET /api/hunts/spider/<id>/export/?format=json|html"""
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        import json as _json
        from datetime import datetime
        from django.http import HttpResponse
        from core.modules.spider import get_session

        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        fmt = request.query_params.get("format", "json").lower()
        urls        = s.get("urls") or []
        hidden      = s.get("hidden_paths") or []
        target      = s.get("url", "")
        ts          = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        fname_base  = f"spider_{session_id[:8]}"

        if fmt == "json":
            payload = {
                "session_id":   session_id,
                "target":       target,
                "exported_at":  ts,
                "stats": {
                    "visited":  s.get("visited", 0),
                    "total_urls": len(urls),
                    "hidden_found": len(hidden),
                },
                "urls":         urls,
                "hidden_paths": hidden,
            }
            resp = HttpResponse(
                _json.dumps(payload, indent=2),
                content_type="application/json",
            )
            resp["Content-Disposition"] = f'attachment; filename="{fname_base}.json"'
            return resp

        if fmt == "html":
            rows = ""
            for u in urls:
                status_cls = "ok" if (u.get("status") or 0) < 400 else "err"
                rows += (
                    f'<tr class="{status_cls}">'
                    f'<td><a href="{u.get("final_url") or u.get("url","")}" target="_blank">'
                    f'{u.get("url","")}</a></td>'
                    f'<td>{u.get("status","")}</td>'
                    f'<td>{u.get("content_type","")}</td>'
                    f'<td>{u.get("depth","")}</td>'
                    f'</tr>'
                )
            hidden_rows = ""
            for h in hidden:
                risk_cls = {"high": "risk-h", "critical": "risk-c", "medium": "risk-m"}.get(h.get("risk",""), "")
                hidden_rows += (
                    f'<tr class="{risk_cls}">'
                    f'<td>{h.get("path","")}</td>'
                    f'<td>{h.get("status","")}</td>'
                    f'<td>{h.get("risk","")}</td>'
                    f'<td>{", ".join(h.get("sensitive") or []) or "-"}</td>'
                    f'</tr>'
                )
            html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8">
<title>Spider Report – {target}</title>
<style>
 body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:24px;}}
 h1{{color:#58a6ff;}} h2{{color:#8b949e;font-size:1em;margin-top:2em;}}
 table{{border-collapse:collapse;width:100%;margin-top:8px;}}
 th{{background:#161b22;color:#8b949e;padding:6px 10px;text-align:left;font-size:.75em;border:1px solid #30363d;}}
 td{{padding:5px 10px;font-size:.75em;border:1px solid #21262d;word-break:break-all;}}
 tr.ok td{{color:#c9d1d9;}} tr.err td{{color:#f85149;}}
 tr.risk-h td{{color:#e3b341;}} tr.risk-c td{{color:#f85149;}} tr.risk-m td{{color:#58a6ff;}}
 a{{color:#58a6ff;text-decoration:none;}}
 .meta{{color:#8b949e;font-size:.8em;margin-bottom:1.5em;}}
</style>
</head>
<body>
<h1>Spider Report</h1>
<div class="meta">
 Target: <strong>{target}</strong> &nbsp;|&nbsp;
 URLs visited: <strong>{s.get("visited",0)}</strong> &nbsp;|&nbsp;
 Hidden paths found: <strong>{len(hidden)}</strong> &nbsp;|&nbsp;
 Exported: {ts}
</div>
<h2>Crawled URLs ({len(urls)})</h2>
<table>
 <thead><tr><th>URL</th><th>Status</th><th>Content-Type</th><th>Depth</th></tr></thead>
 <tbody>{rows}</tbody>
</table>
{"<h2>Hidden / Sensitive Paths (" + str(len(hidden)) + ")</h2><table><thead><tr><th>Path</th><th>Status</th><th>Risk</th><th>Sensitive</th></tr></thead><tbody>" + hidden_rows + "</tbody></table>" if hidden else ""}
</body></html>"""
            resp = HttpResponse(html, content_type="text/html")
            resp["Content-Disposition"] = f'attachment; filename="{fname_base}.html"'
            return resp

        return Response({"detail": f"Unknown format '{fmt}'. Use json or html."}, status=400)


# ─────────────────────────────────────────────────────────────────────────────
#  Auth Config
# ─────────────────────────────────────────────────────────────────────────────

class AuthConfigViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    ordering           = ["-updated_at"]

    def get_queryset(self):
        qs          = AuthConfig.objects.filter(created_by=self.request.user)
        target_host = self.request.query_params.get("target_host")
        if target_host:
            qs = qs.filter(target_host__icontains=target_host)
        return qs

    def get_serializer_class(self):
        if self.action == "list":
            return AuthConfigListSerializer
        return AuthConfigSerializer

    @action(detail=True, methods=["post"])
    def test(self, request, pk=None):
        auth_cfg = self.get_object()
        target   = (request.data.get("target") or "").strip() or auth_cfg.target_host
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return _run_auth_test(auth_cfg.to_auth_config_dict(), target)

    @action(detail=False, methods=["post"], url_path="test_inline")
    def test_inline(self, request):
        auth_type = request.data.get("auth_type", "none")
        config    = request.data.get("config", {})
        target    = (request.data.get("target") or "").strip()
        if not target:
            return Response(
                {"detail": "target is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return _run_auth_test({"auth_type": auth_type, "config": config}, target)


def _run_auth_test(auth_config_dict: dict, target: str) -> Response:
    """Sync wrapper: runs AuthManager.test_connection in a fresh event loop."""
    sys.path.insert(0, _CORE_ROOT)
    from core.auth_manager import AuthManager

    mgr = AuthManager(auth_config_dict)
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(mgr.test_connection(target))
    except Exception as exc:
        result = {
            "status":          0,
            "authenticated":   False,
            "message":         f"Test failed: {exc}",
            "final_url":       target,
            "headers_applied": [],
            "cookies_set":     [],
            "body_preview":    "",
        }
    finally:
        loop.close()
    return Response(result, status=status.HTTP_200_OK)


# ─────────────────────────────────────────────────────────────────────────────
#  Vuln Docs
# ─────────────────────────────────────────────────────────────────────────────

class VulnDocsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.vuln_docs import VULN_DOCS

        docs = list(VULN_DOCS)

        vuln_id = request.query_params.get("id")
        if vuln_id:
            docs = [d for d in docs if d["id"].lower() == vuln_id.lower()]

        category = request.query_params.get("category")
        if category:
            docs = [d for d in docs if d["category"].lower() == category.lower()]

        severity = request.query_params.get("severity")
        if severity:
            docs = [d for d in docs if d["severity"].lower() == severity.lower()]

        return Response(docs)


# ─────────────────────────────────────────────────────────────────────────────
#  Manual Probe
# ─────────────────────────────────────────────────────────────────────────────

class ManualProbeView(APIView):
    """POST /api/probe/ - fuzz payloads against a target URL."""

    permission_classes = [IsAuthenticated]
    MAX_PAYLOADS       = 200
    MAX_TIMEOUT        = 30

    def post(self, request):
        url_template   = (request.data.get("url_template") or "").strip()
        method         = (request.data.get("method") or "GET").upper()
        custom_headers = dict(request.data.get("headers") or {})
        body_template  = request.data.get("body_template") or ""
        payloads       = request.data.get("payloads") or []
        fuzz_marker    = request.data.get("fuzz_marker") or "FUZZ"
        timeout_sec    = min(int(request.data.get("timeout") or 10), self.MAX_TIMEOUT)
        encode_url     = bool(request.data.get("encode_url", True))

        if not url_template:
            return Response({"error": "url_template is required"}, status=400)
        if method not in (
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
        ):
            return Response({"error": f"Invalid method: {method}"}, status=400)
        if not isinstance(payloads, list):
            return Response({"error": "payloads must be a list"}, status=400)
        if len(payloads) > self.MAX_PAYLOADS:
            return Response(
                {"error": f"Max {self.MAX_PAYLOADS} payloads per probe"},
                status=400,
            )
        if not payloads:
            return Response({"error": "payloads list is empty"}, status=400)

        loop = asyncio.new_event_loop()
        try:
            results = loop.run_until_complete(
                self._run_probes(
                    url_template, method, custom_headers, body_template,
                    payloads, fuzz_marker, timeout_sec, encode_url,
                )
            )
        finally:
            loop.close()

        return Response({"results": results, "total": len(results)})

    async def _run_probes(
        self,
        url_template,
        method,
        custom_headers,
        body_template,
        payloads,
        fuzz_marker,
        timeout_sec,
        encode_url,
    ):
        import aiohttp as _aiohttp
        import json   as _json
        from core import scan_proxy as _scan_proxy

        from urllib.parse import urlparse as _urlparse
        _probe_host  = _urlparse(url_template).hostname or ''
        connector    = _scan_proxy.make_connector(limit=5, target_host=_probe_host)
        timeout      = _aiohttp.ClientTimeout(total=timeout_sec)
        base_headers = {
            "User-Agent": "DS1Hunter/1.0 ManualProbe",
            **{k: str(v) for k, v in custom_headers.items()},
        }

        results = []
        async with _aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=base_headers,
        ) as session:
            for idx, payload in enumerate(payloads):
                payload_str = str(payload)
                encoded     = quote(payload_str, safe="") if encode_url else payload_str
                req_url     = url_template.replace(fuzz_marker, encoded)
                req_body    = (
                    body_template.replace(fuzz_marker, payload_str)
                    if body_template else None
                )

                kwargs = {}
                if req_body:
                    try:
                        kwargs["json"] = _json.loads(req_body)
                    except Exception:
                        kwargs["data"] = req_body.encode()

                t0 = _time.monotonic()
                try:
                    method_fn = getattr(session, method.lower(), None)
                    if method_fn is None:
                        results.append({
                            "index":        idx + 1,
                            "payload":      payload_str,
                            "url":          req_url,
                            "status":       0,
                            "elapsed_ms":   0,
                            "size":         0,
                            "body":         "",
                            "resp_headers": {},
                            "error":        f"Unsupported method {method}",
                        })
                        continue

                    async with method_fn(req_url, **kwargs) as resp:
                        elapsed_ms = int((_time.monotonic() - t0) * 1000)
                        body_text  = await resp.text(errors="replace")
                        results.append({
                            "index":        idx + 1,
                            "payload":      payload_str,
                            "url":          req_url,
                            "status":       resp.status,
                            "elapsed_ms":   elapsed_ms,
                            "size":         len(body_text),
                            "body":         body_text[:4000],
                            "resp_headers": dict(resp.headers),
                            "error":        None,
                        })
                except Exception as exc:
                    elapsed_ms = int((_time.monotonic() - t0) * 1000)
                    results.append({
                        "index":        idx + 1,
                        "payload":      payload_str,
                        "url":          req_url,
                        "status":       0,
                        "elapsed_ms":   elapsed_ms,
                        "size":         0,
                        "body":         "",
                        "resp_headers": {},
                        "error":        str(exc),
                    })

        return results


# ─────────────────────────────────────────────────────────────────────────────
#  Mobile Process Views
# ─────────────────────────────────────────────────────────────────────────────

class MobileProcessListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.mobile_process_manager import get_process_manager
        return Response(get_process_manager().get_all_status())

    def post(self, request):
        from core.mobile_process_manager import (
            get_process_manager,
            list_dynamic_test_templates,
            build_dynamic_command,
        )

        app_name     = (request.data.get("app_name")     or "").strip()
        device_id    = (request.data.get("device_id")    or "").strip() or None
        test_type    = (request.data.get("test_type")    or "").strip()
        package_name = (request.data.get("package_name") or "").strip()
        pid          = (request.data.get("pid")          or "").strip()
        command      = request.data.get("command")
        extra_args   = request.data.get("extra_args")

        if not test_type:
            return Response(
                {"detail": "test_type is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # PID-based attach: auto-label, use pid as the target argument
        pid_attach_types = {"frida_attach_pid", "adb_logcat_pid"}
        if not app_name:
            if pid:
                app_name = f"PID {pid}"
            elif package_name:
                app_name = package_name
            else:
                return Response(
                    {"detail": "app_name or package_name is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        mgr = get_process_manager()

        if command and isinstance(command, list):
            proc = mgr.create_process(
                app_name=app_name,
                device_id=device_id or "",
                test_type=test_type,
                command=command,
                created_by=request.user.username,
            )
        else:
            # For PID-based templates use pid as the target; others use package_name
            target = pid if test_type in pid_attach_types and pid else package_name
            if not target:
                return Response(
                    {"detail": "package_name (or pid for attach types) is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            templates = list_dynamic_test_templates()
            if test_type not in templates:
                return Response(
                    {"detail": f"Unknown test_type. Available: {list(templates.keys())}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            proc = mgr.create_dynamic_process(
                app_name=app_name,
                device_id=device_id or "",
                test_type=test_type,
                package_name=target,
                created_by=request.user.username,
                extra_args=extra_args,
            )

        mgr.start_process_async(proc.process_id)
        return Response(
            proc.to_dict(include_output=False),
            status=status.HTTP_201_CREATED,
        )


class MobileProcessDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, process_id):
        from core.mobile_process_manager import get_process_manager
        proc = get_process_manager().get_process(process_id)
        if not proc:
            return Response(
                {"detail": "Not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(proc.to_dict(include_output=True, output_limit=200))

    def delete(self, request, process_id):
        from core.mobile_process_manager import get_process_manager
        ok = get_process_manager().delete_process(process_id)
        if not ok:
            return Response(
                {"detail": "Process not found or still running."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({"detail": "Deleted."})

    def post(self, request, process_id):
        from core.mobile_process_manager import get_process_manager
        mgr  = get_process_manager()
        proc = mgr.get_process(process_id)
        if not proc:
            return Response(
                {"detail": "Not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        act = (
            request.data.get("action")
            or request.query_params.get("action")
            or request.path.strip("/").split("/")[-1]
        )

        ACTION_MAP = {
            "start":  mgr.start_process_async,
            "stop":   mgr.stop_process,
            "pause":  mgr.pause_process,
            "resume": mgr.resume_process,
        }

        handler = ACTION_MAP.get(act)
        if handler is None:
            return Response(
                {"detail": f"Unknown action: {act}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        ok = handler(process_id)
        if not ok:
            return Response(
                {"detail": f"Cannot {act} process."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({
            "detail":  f"{act.capitalize()} requested.",
            "process": proc.to_dict(include_output=False),
        })

# ── Device / Execution Analysis ───────────────────────────────────────────────

class MobileDeviceView(APIView):
    """
    GET  /api/mobile/device/           - list connected ADB devices
    POST /api/mobile/device/           - create + start a device analysis session
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.mobile_process_manager import list_adb_devices, list_analysis_sessions
        return Response({
            "devices":  list_adb_devices(),
            "sessions": list_analysis_sessions(),
        })

    def post(self, request):
        from core.mobile_process_manager import (
            create_analysis_session, start_analysis_session,
        )
        package_name   = (request.data.get("package_name")   or "").strip()
        device_id      = (request.data.get("device_id")      or "").strip()
        include_frida  = bool(request.data.get("include_frida", True))

        sid = create_analysis_session(
            package_name=package_name,
            device_id=device_id,
            include_frida=include_frida,
        )
        start_analysis_session(sid)
        return Response({"session_id": sid, "status_msg": "Started"},
                        status=status.HTTP_201_CREATED)


class MobileDeviceAnalysisDetailView(APIView):
    """
    GET    /api/mobile/device/<sid>/  - poll session status + results
    DELETE /api/mobile/device/<sid>/  - delete completed session
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.mobile_process_manager import get_analysis_session
        s = get_analysis_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(s)

    def delete(self, request, session_id):
        from core.mobile_process_manager import delete_analysis_session
        ok = delete_analysis_session(session_id)
        if not ok:
            return Response({"detail": "Not found or still running."},
                            status=status.HTTP_400_BAD_REQUEST)
        return Response({"detail": "Deleted."})
