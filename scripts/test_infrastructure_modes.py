"""
TrustXCloud Infrastructure Mode Tests.

Verifies that the same processing pipeline works correctly in both modes.

LOCAL mode tests (can run without AWS credentials):
  - InfrastructureFactory creates LOCAL bundle correctly
  - LocalEventSource loads sample CloudTrail records
  - LocalQueueTransport delivers records to a callback
  - LocalPersistenceAdapter saves and retrieves decisions
  - PipelineWorker processes events through real ML/XAI pipeline
  - Full end-to-end: local event â†’ ML â†’ XAI â†’ persist â†’ API

REAL AWS mode tests (marked as REQUIRES_AWS_CREDENTIALS):
  - Cannot pass without valid AWS credentials + configured resources
  - These tests are SKIPPED, not FAILED, when credentials are unavailable

Usage:
    python scripts/test_infrastructure_modes.py
    python scripts/test_infrastructure_modes.py --real    # also runs AWS tests
"""

import os
import sys
import json
import time
import argparse
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# Force LOCAL mode for the default test run
os.environ.setdefault("TRUSTXCLOUD_AWS_MODE", "local")

PASS = "[PASS]"
FAIL = "[FAIL]"
SKIP = "[SKIP]"
INFO = "[INFO]"

_results: List[Tuple[str, str, str]] = []  # (status, name, detail)


def test(name: str):
    """Decorator-style test runner."""
    def _run(fn):
        try:
            fn()
            _results.append((PASS, name, ""))
            print(f"  {PASS} {name}")
        except AssertionError as e:
            _results.append((FAIL, name, str(e)))
            print(f"  {FAIL} {name}: {e}")
        except Exception as e:
            _results.append((FAIL, name, f"{type(e).__name__}: {e}"))
            print(f"  {FAIL} {name}: {type(e).__name__}: {e}")
            traceback.print_exc()
        return fn
    return _run


def skip(name: str, reason: str):
    _results.append((SKIP, name, reason))
    print(f"  {SKIP} {name}: {reason}")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Section 1: Infrastructure Interfaces
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

print("\n" + "=" * 70)
print("  SECTION 1: Infrastructure Interfaces")
print("=" * 70)

@test("InfrastructureMode enum values")
def _():
    from backend.infrastructure.interfaces import InfrastructureMode
    assert InfrastructureMode.LOCAL.value == "local"
    assert InfrastructureMode.REAL.value == "real"

@test("InfrastructureBundle describes itself correctly")
def _():
    from backend.infrastructure.interfaces import InfrastructureBundle, InfrastructureMode
    from backend.infrastructure.local_adapters import (
        LocalEventSourceAdapter, LocalQueueTransport,
        LocalPersistenceAdapter, LocalHealthAdapter,
    )
    src = LocalEventSourceAdapter()
    pers = LocalPersistenceAdapter()
    trans = LocalQueueTransport(src)
    health = LocalHealthAdapter(src, trans, pers)
    bundle = InfrastructureBundle(
        mode=InfrastructureMode.LOCAL,
        event_source=src,
        transport=trans,
        persistence=pers,
        health=health,
    )
    desc = bundle.describe()
    assert "LOCAL" in desc or "SIMULATED" in desc, f"Expected LOCAL/SIMULATED in desc: {desc}"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Section 2: InfrastructureFactory (LOCAL mode)
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

print("\n" + "=" * 70)
print("  SECTION 2: InfrastructureFactory â€” LOCAL mode")
print("=" * 70)

@test("Factory creates LOCAL bundle when TRUSTXCLOUD_AWS_MODE=local")
def _():
    os.environ["TRUSTXCLOUD_AWS_MODE"] = "local"
    from backend.infrastructure import InfrastructureFactory, InfrastructureMode
    bundle = InfrastructureFactory.create()
    assert bundle.mode == InfrastructureMode.LOCAL, f"Expected LOCAL, got {bundle.mode}"

@test("Factory creates LOCAL bundle when TRUSTXCLOUD_AWS_MODE is unset")
def _():
    os.environ.pop("TRUSTXCLOUD_AWS_MODE", None)
    from backend.infrastructure import InfrastructureFactory, InfrastructureMode
    # Re-import factory to reset module-level state
    import importlib
    import backend.infrastructure.factory as fmod
    importlib.reload(fmod)
    bundle = fmod.InfrastructureFactory.create()
    assert bundle.mode == InfrastructureMode.LOCAL
    os.environ["TRUSTXCLOUD_AWS_MODE"] = "local"  # restore

@test("Factory raises RuntimeError in REAL mode with missing SQS URL")
def _():
    os.environ["TRUSTXCLOUD_AWS_MODE"] = "real"
    os.environ.pop("AWS_SQS_QUEUE_URL", None)
    try:
        from backend.infrastructure import InfrastructureFactory
        import importlib
        import backend.infrastructure.factory as fmod
        importlib.reload(fmod)
        try:
            fmod.InfrastructureFactory.create()
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "AWS_SQS_QUEUE_URL" in str(e), f"Expected SQS URL mention: {e}"
    finally:
        os.environ["TRUSTXCLOUD_AWS_MODE"] = "local"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Section 3: LOCAL Event Source
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

print("\n" + "=" * 70)
print("  SECTION 3: LOCAL Event Source Adapter")
print("=" * 70)

@test("LocalEventSourceAdapter loads sample CloudTrail events from disk")
def _():
    from backend.infrastructure.local_adapters import LocalEventSourceAdapter
    src = LocalEventSourceAdapter()
    assert src._loaded, "Expected _loaded=True"
    assert len(src._records) > 0, "Expected sample events to be loaded"
    print(f"    {INFO} Loaded {len(src._records)} sample events")

@test("LocalEventSourceAdapter.get_sample_records returns CloudTrailRecord objects")
def _():
    from backend.infrastructure.local_adapters import LocalEventSourceAdapter
    from backend.infrastructure.interfaces import CloudTrailRecord
    src = LocalEventSourceAdapter()
    records = src.get_sample_records(limit=5)
    assert len(records) <= 5
    assert len(records) > 0
    for r in records:
        assert isinstance(r, CloudTrailRecord), f"Expected CloudTrailRecord, got {type(r)}"
        assert r.event_id, "event_id should not be empty"
        assert r.event_name, "event_name should not be empty"

@test("LocalEventSourceAdapter.health returns SIMULATED status")
def _():
    from backend.infrastructure.local_adapters import LocalEventSourceAdapter
    from backend.infrastructure.interfaces import InfrastructureMode
    src = LocalEventSourceAdapter()
    h = src.health()
    assert h.status == "SIMULATED", f"Expected SIMULATED, got {h.status}"
    assert h.mode == InfrastructureMode.LOCAL
    assert "SIMULATED" in h.message or "LOCAL" in h.message or "sample" in h.message.lower()

@test("CloudTrailRecord.to_raw_dict returns normalizer-compatible dict")
def _():
    from backend.infrastructure.local_adapters import LocalEventSourceAdapter
    src = LocalEventSourceAdapter()
    records = src.get_sample_records(limit=1)
    assert records
    raw = records[0].to_raw_dict()
    # Must have minimum fields for validate_cloudtrail_record
    for field in ["eventID", "eventTime", "eventName", "eventSource", "awsRegion"]:
        assert field in raw, f"Missing required field: {field}"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Section 4: LOCAL Persistence
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

print("\n" + "=" * 70)
print("  SECTION 4: LOCAL Persistence Adapter")
print("=" * 70)

@test("LocalPersistenceAdapter saves and retrieves a decision")
def _():
    from backend.infrastructure.local_adapters import LocalPersistenceAdapter
    pers = LocalPersistenceAdapter()
    ml_result = {
        "decision": "THREAT",
        "confidence": 0.92,
        "xgboost_probability": 0.94,
        "tabnet_probability": 0.90,
        "model_agreement": True,
        "top_shap_features": [{"feature": "call_frequency_10m", "value": 42.0, "shap_value": 2.1}],
        "llm_narrative": "High-frequency IAM privilege escalation detected.",
        "event_summary": {"identity_arn": "arn:aws:iam::123:user/test", "event_name": "CreateAccessKey"},
    }
    decision_id = pers.save_decision(ml_result)
    assert decision_id, "Expected non-empty decision_id"
    retrieved = pers.get_decision(decision_id)
    assert retrieved is not None, "Expected to retrieve saved decision"
    assert retrieved.get("decision_id") == decision_id

@test("LocalPersistenceAdapter.list_decisions returns recent records")
def _():
    from backend.infrastructure.local_adapters import LocalPersistenceAdapter
    pers = LocalPersistenceAdapter()
    for i in range(5):
        pers.save_decision({"decision": "BENIGN", "confidence": 0.8, "model_version": "v3.0"})
    decisions = pers.list_decisions(limit=3)
    assert len(decisions) <= 3

@test("LocalPersistenceAdapter.health returns SIMULATED")
def _():
    from backend.infrastructure.local_adapters import LocalPersistenceAdapter
    from backend.infrastructure.interfaces import InfrastructureMode
    pers = LocalPersistenceAdapter()
    h = pers.health()
    assert h.status == "SIMULATED"
    assert h.mode == InfrastructureMode.LOCAL


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Section 5: LOCAL Transport
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

print("\n" + "=" * 70)
print("  SECTION 5: LOCAL Queue Transport")
print("=" * 70)

@test("LocalQueueTransport.enqueue_raw delivers record to callback")
def _():
    import threading
    from backend.infrastructure.local_adapters import (
        LocalEventSourceAdapter, LocalQueueTransport
    )
    src = LocalEventSourceAdapter()
    transport = LocalQueueTransport(src)

    received = []
    event = threading.Event()

    def on_records(records):
        received.extend(records)
        event.set()

    transport.start_polling(on_records=on_records)
    time.sleep(0.2)

    raw_record = src.get_raw_records(limit=1)[0]
    transport.enqueue_raw(raw_record)

    delivered = event.wait(timeout=5)
    transport.stop()

    assert delivered, "Callback was not called within 5 seconds"
    assert len(received) == 1, f"Expected 1 record delivered, got {len(received)}"
    assert received[0].get("eventName") == raw_record.get("eventName")

@test("LocalQueueTransport.get_stats returns mode=LOCAL")
def _():
    from backend.infrastructure.local_adapters import (
        LocalEventSourceAdapter, LocalQueueTransport
    )
    src = LocalEventSourceAdapter()
    transport = LocalQueueTransport(src)
    stats = transport.get_stats()
    assert stats.get("mode") == "LOCAL"
    assert stats.get("sqsConfigured") is False


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Section 6: LOCAL Health Adapter
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

print("\n" + "=" * 70)
print("  SECTION 6: LOCAL Infrastructure Health")
print("=" * 70)

@test("LocalHealthAdapter reports awsConnected=False")
def _():
    from backend.infrastructure.local_adapters import (
        LocalEventSourceAdapter, LocalQueueTransport,
        LocalPersistenceAdapter, LocalHealthAdapter,
    )
    src = LocalEventSourceAdapter()
    pers = LocalPersistenceAdapter()
    trans = LocalQueueTransport(src)
    health = LocalHealthAdapter(src, trans, pers)
    h = health.get_overall_health()
    assert h.get("awsConnected") is False, f"Expected awsConnected=False, got {h.get('awsConnected')}"
    assert h.get("overall") == "SIMULATED"
    assert h.get("mode") == "local"
    assert h.get("modeLabel") == "LOCAL / SIMULATED"

@test("LocalHealthAdapter reports SIMULATED for all components")
def _():
    from backend.infrastructure.local_adapters import (
        LocalEventSourceAdapter, LocalQueueTransport,
        LocalPersistenceAdapter, LocalHealthAdapter,
    )
    src = LocalEventSourceAdapter()
    pers = LocalPersistenceAdapter()
    trans = LocalQueueTransport(src)
    health = LocalHealthAdapter(src, trans, pers)
    h = health.get_overall_health()
    components = h.get("components", {})
    for key in ["eventSource", "transport", "persistence", "sqs", "dynamodb", "cloudtrail"]:
        assert key in components, f"Missing component: {key}"
        assert components[key]["status"] == "SIMULATED", (
            f"Component {key} should be SIMULATED, got {components[key]['status']}"
        )


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Section 7: DynamoDBRepository â†’ PersistenceAdapter delegation
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

print("\n" + "=" * 70)
print("  SECTION 7: DynamoDBRepository adapter delegation")
print("=" * 70)

@test("DynamoDBRepository delegates save_decision to LocalPersistenceAdapter")
def _():
    from backend.infrastructure.local_adapters import LocalPersistenceAdapter
    from backend.repositories.dynamodb_repository import DynamoDBRepository
    pers = LocalPersistenceAdapter()
    repo = DynamoDBRepository(persistence_adapter=pers)
    decision_id = repo.save_decision({
        "decision": "THREAT", "confidence": 0.88, "model_version": "v3.0",
        "event_summary": {"identity_arn": "arn:aws:iam::123:user/test", "event_name": "PutUserPolicy"},
    })
    assert decision_id, "Expected a decision_id"
    assert pers._total_saved == 1, "LocalPersistenceAdapter should have recorded 1 save"

@test("DynamoDBRepository.is_live returns False in LOCAL mode")
def _():
    from backend.infrastructure.local_adapters import LocalPersistenceAdapter
    from backend.repositories.dynamodb_repository import DynamoDBRepository
    pers = LocalPersistenceAdapter()
    repo = DynamoDBRepository(persistence_adapter=pers)
    assert repo.is_live is False, f"Expected is_live=False, got {repo.is_live}"

@test("DynamoDBRepository works without persistence_adapter (legacy fallback)")
def _():
    from backend.repositories.dynamodb_repository import DynamoDBRepository
    repo = DynamoDBRepository()  # no adapter â€” legacy mode
    # Should not raise
    decision_id = repo.save_decision({"decision": "BENIGN", "confidence": 0.7, "model_version": "v3.0"})
    assert decision_id, "Expected a decision_id from legacy fallback"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Section 8: PipelineWorker â€” LOCAL end-to-end
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

print("\n" + "=" * 70)
print("  SECTION 8: PipelineWorker â€” LOCAL end-to-end")
print("=" * 70)

@test("PipelineWorker loads and CloudSecurityAnalyzer is available")
def _():
    try:
        from src.predict_and_explain import CloudSecurityAnalyzer
        analyzer = CloudSecurityAnalyzer()
        assert analyzer is not None
    except Exception as e:
        raise AssertionError(f"CloudSecurityAnalyzer not available: {e}")

@test("PipelineWorker.ingest_raw â€” sample event â†’ real ML â†’ real XAI â†’ persist")
def _():
    """
    End-to-end LOCAL mode test.
    Sends a real-format sample CloudTrail event through:
      validate â†’ normalize â†’ XGBoost V3 + TabNet V3 â†’ SHAP â†’ LIME â†’ faithfulness â†’ LLM fallback â†’ persist
    """
    from backend.infrastructure.local_adapters import (
        LocalEventSourceAdapter, LocalQueueTransport,
        LocalPersistenceAdapter,
    )
    from backend.infrastructure.interfaces import InfrastructureMode
    from backend.infrastructure.pipeline_worker import PipelineWorker
    from src.predict_and_explain import CloudSecurityAnalyzer

    src = LocalEventSourceAdapter()
    pers = LocalPersistenceAdapter()
    transport = LocalQueueTransport(src)
    analyzer = CloudSecurityAnalyzer()

    worker = PipelineWorker(
        mode=InfrastructureMode.LOCAL,
        transport=transport,
        persistence=pers,
        analyzer=analyzer,
    )

    # Get a real sample record
    raw_records = src.get_raw_records(limit=1)
    assert raw_records, "No sample records available"
    raw_record = raw_records[0]

    t0 = time.time()
    ml_result = worker.ingest_raw(raw_record)
    elapsed = time.time() - t0

    print(f"    {INFO} Inference completed in {elapsed*1000:.1f}ms")

    # Validate ML result structure
    assert "decision" in ml_result, "Missing 'decision' in ml_result"
    assert ml_result["decision"] in ("BENIGN", "THREAT"), (
        f"Invalid decision: {ml_result['decision']}"
    )
    assert "confidence" in ml_result, "Missing 'confidence'"
    assert 0.0 <= float(ml_result["confidence"]) <= 1.0
    assert "xgboost_probability" in ml_result, "Missing XGBoost probability"
    assert "tabnet_probability" in ml_result, "Missing TabNet probability"

    # Validate XAI
    assert "top_shap_features" in ml_result, "Missing SHAP features"
    shap_features = ml_result["top_shap_features"]
    assert len(shap_features) > 0, "Expected at least 1 SHAP feature"

    # Validate faithfulness
    faith = ml_result.get("llm_faithfulness_result", {})
    assert "is_faithful" in faith, "Missing faithfulness result"

    # Validate LLM narration (fallback at minimum)
    assert "llm_narrative" in ml_result, "Missing LLM narrative"
    assert ml_result["llm_narrative"], "LLM narrative should not be empty"

    # Validate persistence
    assert pers._total_saved >= 1, "Expected at least 1 record saved to LocalPersistenceAdapter"

    print(f"    {INFO} decision={ml_result['decision']} confidence={ml_result['confidence']:.4f}")
    print(f"    {INFO} xgb={ml_result['xgboost_probability']:.4f} "
          f"tab={ml_result['tabnet_probability']:.4f}")
    print(f"    {INFO} SHAP features={len(shap_features)} | faithful={faith.get('is_faithful')}")
    print(f"    {INFO} LLM provider={ml_result.get('llm_provider', 'unknown')}")

@test("PipelineWorker raises ValueError for invalid CloudTrail record")
def _():
    from backend.infrastructure.local_adapters import (
        LocalEventSourceAdapter, LocalQueueTransport, LocalPersistenceAdapter,
    )
    from backend.infrastructure.interfaces import InfrastructureMode
    from backend.infrastructure.pipeline_worker import PipelineWorker
    from src.predict_and_explain import CloudSecurityAnalyzer

    src = LocalEventSourceAdapter()
    worker = PipelineWorker(
        mode=InfrastructureMode.LOCAL,
        transport=LocalQueueTransport(src),
        persistence=LocalPersistenceAdapter(),
        analyzer=CloudSecurityAnalyzer(),
    )
    try:
        worker.ingest_raw({"this": "is not a valid CloudTrail record"})
        assert False, "Expected ValueError"
    except ValueError as e:
        assert "validation failed" in str(e).lower() or "Missing" in str(e)

@test("PipelineWorker live feed callback is called after ingest_raw")
def _():
    import threading
    from backend.infrastructure.local_adapters import (
        LocalEventSourceAdapter, LocalQueueTransport, LocalPersistenceAdapter,
    )
    from backend.infrastructure.interfaces import InfrastructureMode
    from backend.infrastructure.pipeline_worker import PipelineWorker
    from src.predict_and_explain import CloudSecurityAnalyzer

    src = LocalEventSourceAdapter()
    received_events = []
    event = threading.Event()

    def on_processed(evt):
        received_events.append(evt)
        event.set()

    worker = PipelineWorker(
        mode=InfrastructureMode.LOCAL,
        transport=LocalQueueTransport(src),
        persistence=LocalPersistenceAdapter(),
        analyzer=CloudSecurityAnalyzer(),
        on_event_processed=on_processed,
    )
    raw = src.get_raw_records(limit=1)[0]
    worker.ingest_raw(raw)

    assert event.is_set(), "Live feed callback not called"
    assert len(received_events) == 1
    evt = received_events[0]
    assert evt.get("dataSource") == "LOCAL_SIMULATED"
    assert evt.get("mlPrediction") in ("BENIGN", "THREAT")
    assert "threatProbability" in evt
    print(f"    {INFO} Live event: {evt.get('eventName')} â†’ {evt.get('mlPrediction')}")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Section 9: REAL AWS mode (skipped without credentials)
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

print("\n" + "=" * 70)
print("  SECTION 9: REAL AWS mode (requires credentials)")
print("=" * 70)

_run_real = "--real" in sys.argv

def _check_aws_credentials() -> bool:
    try:
        import boto3
        sts = boto3.client("sts", region_name="eu-north-1")
        sts.get_caller_identity()
        return True
    except Exception:
        return False

if not _run_real:
    skip("RealSQSTransport â€” credentials check", "Pass --real to run AWS tests")
    skip("RealDynamoDBPersistenceAdapter â€” table check", "Pass --real to run AWS tests")
    skip("RealCloudTrailEventSource â€” LookupEvents check", "Pass --real to run AWS tests")
    skip("Full REAL mode end-to-end", "Pass --real to run AWS tests")
else:
    _has_creds = _check_aws_credentials()
    if not _has_creds:
        skip("REAL AWS tests", "Valid AWS credentials not available (sts get-caller-identity failed)")
    else:
        @test("REAL mode: STS get-caller-identity succeeds")
        def _():
            import boto3
            sts = boto3.client("sts", region_name="eu-north-1")
            identity = sts.get_caller_identity()
            assert identity.get("Account"), "Expected Account in identity"
            print(f"    {INFO} account={identity.get('Account')} arn={identity.get('Arn')}")

        @test("REAL mode: CloudTrail LookupEvents is accessible")
        def _():
            from backend.infrastructure.real_aws_adapters import RealCloudTrailEventSource
            src = RealCloudTrailEventSource(region="eu-north-1")
            h = src.health()
            assert h.status == "HEALTHY", f"Expected HEALTHY, got {h.status}: {h.message}"

        @test("REAL mode: RealDynamoDBPersistenceAdapter health check")
        def _():
            from backend.infrastructure.real_aws_adapters import RealDynamoDBPersistenceAdapter
            pers = RealDynamoDBPersistenceAdapter(region="eu-north-1", table_name="CloudSecurityDecisions")
            h = pers.health()
            # Either HEALTHY (table exists) or ERROR with specific message
            assert h.status in ("HEALTHY", "ERROR"), f"Unexpected status: {h.status}"
            print(f"    {INFO} DynamoDB status: {h.status} â€” {h.message}")

        if os.environ.get("AWS_SQS_QUEUE_URL"):
            @test("REAL mode: RealSQSTransport health check")
            def _():
                from backend.infrastructure.real_aws_adapters import RealSQSTransport
                transport = RealSQSTransport(
                    queue_url=os.environ["AWS_SQS_QUEUE_URL"],
                    region="eu-north-1",
                )
                h = transport.health()
                assert h.status == "HEALTHY", f"Expected HEALTHY, got {h.status}: {h.message}"
        else:
            skip("REAL mode: SQS transport", "AWS_SQS_QUEUE_URL not configured")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Summary
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

print("\n" + "=" * 70)
passed = sum(1 for s, _, _ in _results if s == PASS)
failed = sum(1 for s, _, _ in _results if s == FAIL)
skipped = sum(1 for s, _, _ in _results if s == SKIP)
total = len(_results)

if failed:
    print(f"FAILURES:")
    for status, name, detail in _results:
        if status == FAIL:
            print(f"  {FAIL} {name}")
            if detail:
                print(f"       {detail}")

print(f"\nSUMMARY: {passed} PASSED, {failed} FAILED, {skipped} SKIPPED out of {total} tests")
print("=" * 70)

sys.exit(0 if failed == 0 else 1)
