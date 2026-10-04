"""
Infrastructure Factory for TrustXCloud.

Reads TRUSTXCLOUD_AWS_MODE from the environment and returns an
InfrastructureBundle with the appropriate concrete adapters.

TRUSTXCLOUD_AWS_MODE=local (default)
  → LocalEventSourceAdapter, LocalQueueTransport, LocalPersistenceAdapter

TRUSTXCLOUD_AWS_MODE=real
  → RealCloudTrailEventSource, RealSQSTransport, RealDynamoDBPersistenceAdapter
    FAILS with a clear error message if credentials or resources are unavailable.

The factory is the ONLY place that reads TRUSTXCLOUD_AWS_MODE.
The rest of the application is mode-agnostic.
"""

from __future__ import annotations

import logging
import os

from .interfaces import InfrastructureBundle, InfrastructureMode

logger = logging.getLogger("trustxcloud.infrastructure.factory")


class InfrastructureFactory:
    """
    Creates and returns the correct InfrastructureBundle for the configured mode.
    Call once at application startup.
    """

    @staticmethod
    def create() -> InfrastructureBundle:
        """
        Reads TRUSTXCLOUD_AWS_MODE and builds the infrastructure bundle.

        Returns:
            InfrastructureBundle — all adapters wired for the active mode.

        Raises:
            RuntimeError — in REAL mode if credentials or required env vars are missing.
        """
        raw_mode = os.environ.get("TRUSTXCLOUD_AWS_MODE", "local").strip().lower()

        if raw_mode == "real":
            return InfrastructureFactory._create_real()
        else:
            if raw_mode not in ("local", ""):
                logger.warning(
                    f"Unknown TRUSTXCLOUD_AWS_MODE='{raw_mode}'. "
                    "Defaulting to LOCAL mode. Valid values: local, real"
                )
            return InfrastructureFactory._create_local()

    @staticmethod
    def _create_local() -> InfrastructureBundle:
        """Builds the full LOCAL simulation bundle."""
        from .local_adapters import (
            LocalEventSourceAdapter,
            LocalHealthAdapter,
            LocalPersistenceAdapter,
            LocalQueueTransport,
        )

        logger.info("=" * 60)
        logger.info("  TrustXCloud Infrastructure: LOCAL / SIMULATED mode")
        logger.info("  TRUSTXCLOUD_AWS_MODE=local")
        logger.info("  No AWS credentials required.")
        logger.info("=" * 60)

        event_source = LocalEventSourceAdapter()
        persistence = LocalPersistenceAdapter()
        transport = LocalQueueTransport(event_source=event_source)
        health = LocalHealthAdapter(
            event_source=event_source,
            transport=transport,
            persistence=persistence,
        )

        bundle = InfrastructureBundle(
            mode=InfrastructureMode.LOCAL,
            event_source=event_source,
            transport=transport,
            persistence=persistence,
            health=health,
        )
        logger.info(f"[InfrastructureFactory] Bundle created: {bundle.describe()}")
        return bundle

    @staticmethod
    def _create_real() -> InfrastructureBundle:
        """
        Builds the REAL AWS bundle.
        Raises RuntimeError with a clear message if any required resource is misconfigured.
        """
        from .real_aws_adapters import (
            RealAWSHealthAdapter,
            RealCloudTrailEventSource,
            RealDynamoDBPersistenceAdapter,
            RealSQSTransport,
        )

        logger.info("=" * 60)
        logger.info("  TrustXCloud Infrastructure: REAL AWS mode")
        logger.info("  TRUSTXCLOUD_AWS_MODE=real")
        logger.info("  Using boto3 + AWS credential provider chain.")
        logger.info("=" * 60)

        region = os.environ.get("AWS_REGION", "eu-north-1")
        queue_url = os.environ.get("AWS_SQS_QUEUE_URL", "")
        s3_bucket = os.environ.get("AWS_S3_CLOUDTRAIL_BUCKET", "")
        table_name = os.environ.get("DYNAMODB_TABLE_NAME", "CloudSecurityDecisions")

        # Validate required configuration before creating adapters
        errors = []
        if not queue_url:
            errors.append(
                "AWS_SQS_QUEUE_URL is not set. "
                "Format: https://sqs.<region>.amazonaws.com/<account-id>/<queue-name>"
            )

        if errors:
            msg = (
                "TRUSTXCLOUD_AWS_MODE=real is configured but the following "
                "required variables are missing:\n  " + "\n  ".join(errors)
            )
            logger.error(f"[InfrastructureFactory] {msg}")
            raise RuntimeError(msg)

        event_source = RealCloudTrailEventSource(region=region, s3_bucket=s3_bucket or None)
        transport = RealSQSTransport(queue_url=queue_url, region=region, s3_bucket=s3_bucket or None)
        persistence = RealDynamoDBPersistenceAdapter(region=region, table_name=table_name)
        health = RealAWSHealthAdapter(
            region=region,
            event_source=event_source,
            transport=transport,
            persistence=persistence,
        )

        bundle = InfrastructureBundle(
            mode=InfrastructureMode.REAL,
            event_source=event_source,
            transport=transport,
            persistence=persistence,
            health=health,
        )
        logger.info(f"[InfrastructureFactory] Bundle created: {bundle.describe()}")
        return bundle
