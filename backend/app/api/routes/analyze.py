import logging
import uuid

from fastapi import APIRouter, HTTPException, Request

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.models.analyze_request import AnalyzeRequest
from app.services.analyze_pipeline import analyze_content
from app.core.config import settings


router = APIRouter()
logger = logging.getLogger(__name__)


limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.rate_limit_requests}/{settings.rate_limit_window_seconds} seconds"],
)


@router.post("/analyze")
@limiter.limit(f"{settings.rate_limit_requests}/{settings.rate_limit_window_seconds} seconds")
async def analyze_endpoint(payload: AnalyzeRequest, request: Request) -> object:
    req_id = request.headers.get("x-request-id") or str(uuid.uuid4())

    try:
        resp = analyze_content(payload)
        # Avoid returning untrusted content in logs.
        logger.info(
            "analyze completed",
            extra={"request_id": req_id, "input_type": payload.input_type, "risk_level": resp.risk_level},
        )
        return resp
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("analyze failed", extra={"request_id": req_id})
        raise HTTPException(status_code=500, detail="Internal error")

