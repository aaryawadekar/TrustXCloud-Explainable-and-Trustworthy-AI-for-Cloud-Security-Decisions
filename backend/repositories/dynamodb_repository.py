"""
DynamoDB repository layer.

In REAL AWS mode: delegates to RealDynamoDBPersistenceAdapter.
In LOCAL mode:   delegates to LocalPersistenceAdapter.

The PersistenceAdapter is injected at construction time via InfrastructureFactory.
AnalysisService and other callers continue to use this repository class unchanged.
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class DynamoDBRepository:
    """
    Repository interface for ML/XAI decision persistence.
    Delegates all operations to the injected PersistenceAdapter.

    When persistence_adapter is None (legacy/standalone use), falls back
    to a no-op in-memory store so existing code doesn't break.
    """

    def __init__(self, persistence_adapter=None):
        """
        Args:
            persistence_adapter: A PersistenceAdapter instance from
                InfrastructureFactory. Pass None only in standalone scripts
                that don't use the full infrastructure bundle.
        """
        self._adapter = persistence_adapter

        if persistence_adapter is not None:
            # Determine mode for logging
            mode = getattr(
                getattr(persistence_adapter, "health", lambda: None)(),
                "mode",
                "unknown",
            )
            logger.info(
                f"DynamoDBRepository initialized | adapter={type(persistence_adapter).__name__}"
            )
        else:
            # Legacy fallback — build the old DynamoDBSecurityStore directly
            logger.warning(
                "DynamoDBRepository created without a PersistenceAdapter. "
                "Using legacy DynamoDBSecurityStore (LOCAL mock store fallback)."
            )
            self._adapter = self._build_legacy_adapter()

    def _build_legacy_adapter(self):
        """Legacy: wraps the old DynamoDBSecurityStore in a thin adapter-compatible shim."""
        try:
            from aws.dynamodb_store import DynamoDBSecurityStore
            store = DynamoDBSecurityStore()

            class _LegacyShim:
                def save_decision(self, ml_result):
                    return store.put_decision_record(ml_result)

                def get_decision(self, decision_id):
                    mock = getattr(store, "mock_store", [])
                    for item in mock:
                        if item.get("decision_id") == decision_id:
                            return item
                    return None

                def list_decisions(self, limit=50):
                    mock = getattr(store, "mock_store", [])
                    return mock[-limit:]

            return _LegacyShim()
        except Exception as e:
            logger.warning(f"Legacy DynamoDBSecurityStore unavailable: {e}. Using no-op store.")

            class _NoOpShim:
                def save_decision(self, ml_result):
                    import uuid
                    return str(uuid.uuid4())

                def get_decision(self, decision_id):
                    return None

                def list_decisions(self, limit=50):
                    return []

            return _NoOpShim()

    @property
    def is_live(self) -> bool:
        """True if the underlying adapter is a real AWS DynamoDB connection."""
        from backend.infrastructure.interfaces import InfrastructureMode
        h = getattr(self._adapter, "health", None)
        if h:
            try:
                status = h()
                return (
                    getattr(status, "mode", None) == InfrastructureMode.REAL
                    and getattr(status, "status", "") == "HEALTHY"
                )
            except Exception:
                pass
        return False

    def save_decision(self, ml_result: Dict[str, Any]) -> str:
        """Persists an ML/XAI decision record. Returns the unique decision_id."""
        try:
            return self._adapter.save_decision(ml_result)
        except Exception as e:
            logger.error(f"DynamoDBRepository.save_decision failed: {e}")
            import uuid
            return str(uuid.uuid4())

    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a decision by ID. Returns None if not found."""
        try:
            return self._adapter.get_decision(decision_id)
        except Exception as e:
            logger.error(f"DynamoDBRepository.get_decision failed: {e}")
            return None

    def list_decisions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent decisions, up to limit."""
        try:
            return self._adapter.list_decisions(limit=limit)
        except Exception as e:
            logger.error(f"DynamoDBRepository.list_decisions failed: {e}")
            return []
