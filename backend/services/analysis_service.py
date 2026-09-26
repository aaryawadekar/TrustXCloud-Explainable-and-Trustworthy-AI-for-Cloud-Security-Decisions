"""
Analysis service connecting the FastAPI backend to the ML/XAI CloudSecurityAnalyzer engine.
Enforces that CloudSecurityAnalyzer remains the sole source of truth for threat detections.
"""

import time
import logging
from typing import Dict, Any, Optional
from fastapi import HTTPException

from backend.schemas import SecurityAnalysis
from backend.adapters.analysis_adapter import to_security_analysis
from backend.services.events_service import EventsService
from backend.repositories.dynamodb_repository import DynamoDBRepository

logger = logging.getLogger(__name__)


class AnalysisService:
    def __init__(
        self,
        analyzer: Any,
        events_service: EventsService,
        dynamodb_repo: DynamoDBRepository,
    ):
        self.analyzer = analyzer
        self.events_service = events_service
        self.dynamodb_repo = dynamodb_repo
        self._analysis_cache: Dict[str, SecurityAnalysis] = {}

    def get_or_run_analysis(self, event_id: str) -> SecurityAnalysis:
        """
        Runs or retrieves the ML/XAI analysis for the requested event ID.
        Invokes CloudSecurityAnalyzer.analyze_event(raw_event), maps via adapter,
        persists to DynamoDB, and caches in-memory.
        """
        # Return cached analysis if available
        if event_id in self._analysis_cache:
            return self._analysis_cache[event_id]

        # Retrieve raw CloudTrail event payload
        raw_event = self.events_service.get_raw_event(event_id)
        if not raw_event:
            # Check if event exists as SecurityEvent
            sec_event = self.events_service.get_event_by_id(event_id)
            if not sec_event:
                raise HTTPException(
                    status_code=404,
                    detail=f"Security event '{event_id}' not found for analysis",
                )
            
            # Construct standard CloudTrail payload if only SecurityEvent is available
            raw_event = {
                "eventName": sec_event.eventName,
                "eventSource": f"{sec_event.service.lower()}.amazonaws.com",
                "awsRegion": sec_event.region,
                "sourceIPAddress": sec_event.sourceIp,
                "userAgent": sec_event.userAgent,
                "eventTime": sec_event.timestamp,
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": sec_event.user,
                    "arn": sec_event.userArn or f"arn:aws:iam::123456789012:user/{sec_event.user}",
                },
                "requestParameters": sec_event.requestParameters or {},
            }

        if self.analyzer is None:
            raise HTTPException(
                status_code=503,
                detail="CloudSecurityAnalyzer ML engine is currently unavailable in the environment",
            )

        try:
            start_time = time.time()
            ml_result = self.analyzer.analyze_event(raw_event)
            inference_ms = (time.time() - start_time) * 1000.0

            # Convert via adapter
            analysis = to_security_analysis(event_id, ml_result, inference_ms)

            # Update event risk score & classification in events service
            self.events_service.update_event_analysis(
                event_id, analysis.riskScore, analysis.classification
            )

            # Persist decision to DynamoDB
            try:
                self.dynamodb_repo.save_decision(ml_result)
            except Exception as e:
                logger.warning(f"Failed to persist decision to DynamoDB: {e}")

            # Cache
            self._analysis_cache[event_id] = analysis
            return analysis

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Analysis engine execution failed for event {event_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Analysis pipeline execution failed: {str(e)}",
            )
