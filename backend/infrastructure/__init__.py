"""
TrustXCloud Infrastructure Abstraction Layer.

Provides clean interface boundaries between the business/ML layer and
the underlying infrastructure (AWS services or local simulation).

The business layer (SQSWorker, AnalysisService, etc.) depends only on
the abstract interfaces defined here. Concrete implementations are:

  Local (TRUSTXCLOUD_AWS_MODE=local):
    LocalEventSource, LocalQueueTransport, LocalPersistenceStore

  Real AWS (TRUSTXCLOUD_AWS_MODE=real):
    CloudTrailEventSource, SQSTransport, DynamoDBPersistenceStore

Selection is performed by InfrastructureFactory at startup based solely
on the TRUSTXCLOUD_AWS_MODE environment variable.
"""

from .interfaces import (
    EventSourceAdapter,
    EventTransportAdapter,
    PersistenceAdapter,
    InfrastructureHealthAdapter,
    InfrastructureMode,
    InfrastructureBundle,
)
from .factory import InfrastructureFactory

__all__ = [
    "EventSourceAdapter",
    "EventTransportAdapter",
    "PersistenceAdapter",
    "InfrastructureHealthAdapter",
    "InfrastructureMode",
    "InfrastructureBundle",
    "InfrastructureFactory",
]
