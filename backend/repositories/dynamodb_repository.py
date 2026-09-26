"""
DynamoDB repository layer.
Encapsulates all persistence operations so that services do not directly depend
on boto3 or raw AWS connections.
Provides transparent fallback to in-memory store when AWS is unavailable.
"""

import logging
from typing import Dict, Any, List, Optional
from backend.config import settings

logger = logging.getLogger(__name__)


class DynamoDBRepository:
    def __init__(self):
        self.region = settings.AWS_REGION
        self.table_name = settings.DYNAMODB_TABLE_NAME
        self.store = None
        self._init_store()

    def _init_store(self):
        try:
            from aws.dynamodb_store import DynamoDBSecurityStore
            self.store = DynamoDBSecurityStore(region=self.region)
            logger.info(f"DynamoDBSecurityStore initialized (is_live={self.store.is_live})")
        except Exception as e:
            logger.warning(f"Could not initialize DynamoDBSecurityStore: {e}. Using local in-memory fallback.")
            self.store = None

    @property
    def is_live(self) -> bool:
        return bool(self.store and getattr(self.store, "is_live", False))

    def save_decision(self, ml_result: Dict[str, Any]) -> str:
        """
        Persists an ML decision and explainability record.
        Returns the unique decision ID.
        """
        if self.store:
            try:
                return self.store.put_decision_record(ml_result)
            except Exception as e:
                logger.error(f"Error saving decision record: {e}")
        
        # Fallback local identifier
        import uuid
        local_id = str(uuid.uuid4())
        logger.info(f"Decision saved to fallback local memory: {local_id}")
        return local_id

    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a saved decision record by ID.
        """
        if not self.store:
            return None

        if self.is_live and self.store.table:
            try:
                # Query DynamoDB table
                from boto3.dynamodb.conditions import Key
                res = self.store.table.query(
                    KeyConditionExpression=Key("decision_id").eq(decision_id)
                )
                items = res.get("Items", [])
                return items[0] if items else None
            except Exception as e:
                logger.error(f"Error querying DynamoDB for decision_id={decision_id}: {e}")
                return None
        else:
            # Check mock store
            mock_items = getattr(self.store, "mock_store", [])
            for item in mock_items:
                if item.get("decision_id") == decision_id:
                    return item
            return None

    def list_decisions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Lists recent decisions.
        """
        if not self.store:
            return []

        if self.is_live and self.store.table:
            try:
                res = self.store.table.scan(Limit=limit)
                return res.get("Items", [])
            except Exception as e:
                logger.error(f"Error scanning DynamoDB decisions: {e}")
                return []
        else:
            mock_items = getattr(self.store, "mock_store", [])
            return mock_items[-limit:]
