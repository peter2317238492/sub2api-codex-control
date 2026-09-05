from __future__ import annotations

from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEVELOPMENT_SESSION_SECRET = "development-only-change-this-session-secret"
_DEVELOPMENT_METRICS_TOKEN = "development-only-change-this-metrics-token"
_PRODUCTION_SUB2API_BASE_URL = "http://sub2api:8080"
_KNOWN_INSECURE_SECRET_MARKERS = (
    "change-me",
    "changeme",
    "development-only",
    "example-secret",
    "longer-than-32-bytes",
    "never-production",
    "replace-with",
    "test-secret",
    "with-at-least-32-bytes",
)


def _is_known_insecure_secret(value: str) -> bool:
    normalized = value.strip().casefold()
    return any(marker in normalized for marker in _KNOWN_INSECURE_SECRET_MARKERS)


# Bootstrap projections are bounded at write time using compact ensure_ascii
# JSON. These constants include each complete list item, not just payload text.
BOOTSTRAP_BASE_OVERHEAD_BYTES = 4096
BOOTSTRAP_DEVICE_SUMMARY_MAX_BYTES = 16 * 1024
BOOTSTRAP_THREAD_SUMMARY_MAX_BYTES = 12 * 1024
BOOTSTRAP_MODEL_CATALOG_MAX_BYTES = 24 * 1024
BOOTSTRAP_APPROVAL_ITEM_MAX_BYTES = 68 * 1024
BOOTSTRAP_MODEL_MAP_ENTRY_OVERHEAD_BYTES = 128
BOOTSTRAP_CONNECTOR_RELEASE_MAX_BYTES = 16 * 1024


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="CONTROL_",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "Sub2API Codex Control API"
    environment: Literal["development", "test", "production"] = "development"
    api_prefix: str = "/v1"
    external_api_base_path: str = "/codex-api"
    build_version: str = Field(
        default="0.1.12",
        min_length=1,
        max_length=64,
        pattern=r"^[0-9A-Za-z][0-9A-Za-z._+-]*$",
    )
    build_vcs_ref: str = Field(
        default="unknown",
        min_length=1,
        max_length=128,
        pattern=r"^[0-9A-Za-z][0-9A-Za-z._+-]*$",
    )

    database_url: str = "postgresql+asyncpg://codex_control:change-me@postgres:5432/codex_control"
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=200)
    database_pool_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    database_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    database_command_timeout_seconds: float = Field(default=10.0, gt=0, le=60)

    redis_url: str = "redis://redis:6379/0"
    redis_prefix: str = "codex-control:"
    redis_connect_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    redis_command_timeout_seconds: float = Field(default=3.0, gt=0, le=30)

    sub2api_base_url: str = "http://sub2api:8080"
    sub2api_auth_me_path: str = "/api/v1/auth/me"
    sub2api_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    sub2api_verify_tls: bool = True
    sub2api_expected_version: Literal["0.2.0"] = "0.2.0"
    sub2api_expected_commit: Literal["aa23648"] = "aa23648"
    sub2api_contract_marker: str = ""

    connector_expected_version: Literal["0.1.11"] = "0.1.11"
    codex_expected_version: Literal["0.147.0"] = "0.147.0"
    appserver_schema_digest: Literal[
        "511c1b3ca038a80740a5a41ca10a7f925c0f744e582fb9aaa03cc46c6e98b80b"
    ] = "511c1b3ca038a80740a5a41ca10a7f925c0f744e582fb9aaa03cc46c6e98b80b"
    connector_release_metadata_json: str = ""

    session_hmac_secret: SecretStr = SecretStr(_DEVELOPMENT_SESSION_SECRET)
    session_ttl_seconds: int = Field(default=600, ge=300, le=600)
    session_upstream_recheck_seconds: int = Field(default=15, ge=1, le=15)
    recent_auth_max_age_seconds: int = Field(default=300, ge=30, le=600)
    session_token_bytes: int = Field(default=32, ge=32, le=64)
    cookie_name: str = "__Host-codex_control"
    csrf_cookie_name: str = "codex_csrf"
    csrf_header_name: str = "x-csrf-token"
    cookie_secure: bool = True
    cookie_samesite: Literal["strict", "lax"] = "strict"
    allowed_origins_csv: str = "http://localhost:5173,http://testserver"
    session_exchange_limit: int = Field(default=10, ge=1, le=1000)
    owner_max_active_sessions: int = Field(default=32, ge=1, le=256)
    owner_max_session_records: int = Field(default=10000, ge=100, le=100000)

    pairing_ttl_seconds: int = Field(default=600, ge=120, le=900)
    pairing_start_limit: int = Field(default=10, ge=1, le=1000)
    pairing_claim_limit: int = Field(default=10, ge=1, le=1000)
    pairing_poll_limit: int = Field(default=120, ge=1, le=10000)
    pairing_poll_ip_limit: int = Field(default=240, ge=1, le=10000)
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3600)
    trust_forwarded_for: bool = False

    device_access_token_ttl_seconds: int = Field(default=300, ge=60, le=900)
    device_token_issue_limit: int = Field(default=30, ge=1, le=1000)
    device_proof_max_skew_seconds: int = Field(default=60, ge=10, le=300)
    device_nonce_ttl_seconds: int = Field(default=300, ge=60, le=900)
    device_hello_timeout_seconds: int = Field(default=10, ge=3, le=60)
    device_heartbeat_timeout_seconds: int = Field(default=60, ge=15, le=300)
    device_registry_ttl_seconds: int = Field(default=90, ge=30, le=600)
    device_frame_rate_limit: int = Field(default=600, ge=10, le=10000)
    device_max_envelope_bytes: int = Field(default=262144, ge=4096, le=262144)
    device_max_json_depth: int = Field(default=16, ge=4, le=64)
    device_max_json_nodes: int = Field(default=10000, ge=128, le=100000)
    device_max_string_chars: int = Field(default=200000, ge=1024, le=1000000)
    device_max_result_bytes: int = Field(default=524288, ge=4096, le=2097152)
    device_max_event_bytes: int = Field(default=262144, ge=4096, le=1048576)
    device_max_approval_bytes: int = Field(default=65536, ge=2048, le=262144)
    device_max_outbox_frames: int = Field(default=2048, ge=32, le=10000)
    device_max_outbox_bytes: int = Field(default=8388608, ge=65536, le=67108864)
    device_outbox_retention_seconds: int = Field(default=604800, ge=3600, le=2592000)
    device_max_outstanding_commands: int = Field(default=128, ge=1, le=1000)
    device_max_command_records: int = Field(default=10000, ge=128, le=100000)
    owner_max_command_records: int = Field(default=100000, ge=1000, le=1000000)
    device_max_connection_records: int = Field(default=4096, ge=32, le=100000)
    device_max_pending_approvals: int = Field(default=32, ge=1, le=256)
    device_max_approval_records: int = Field(default=4096, ge=32, le=100000)
    browser_event_catchup_limit: int = Field(default=500, ge=1, le=5000)
    browser_event_catchup_max_bytes: int = Field(
        default=1024 * 1024,
        ge=4096,
        le=16 * 1024 * 1024,
    )
    browser_event_retention_days: int = Field(default=30, ge=1, le=365)
    browser_event_max_per_owner: int = Field(default=100000, ge=1000, le=1000000)
    browser_max_connections_per_session: int = Field(default=4, ge=1, le=32)
    browser_max_connections_per_user: int = Field(default=8, ge=1, le=128)
    browser_connection_lease_ttl_seconds: int = Field(default=60, ge=15, le=300)
    bootstrap_max_devices: int = Field(default=100, ge=1, le=1000)
    bootstrap_max_threads: int = Field(default=100, ge=1, le=1000)
    bootstrap_max_pending_approvals: int = Field(default=32, ge=1, le=1000)
    bootstrap_max_models_per_device: int = Field(default=100, ge=1, le=100)
    owner_max_device_records: int = Field(default=1000, ge=100, le=10000)
    owner_max_thread_records: int = Field(default=1000, ge=100, le=100000)
    owner_max_approval_records: int = Field(default=10000, ge=100, le=1000000)
    bootstrap_max_response_bytes: int = Field(
        default=8 * 1024 * 1024,
        ge=64 * 1024,
        le=64 * 1024 * 1024,
    )
    command_ttl_seconds: int = Field(default=30, ge=5, le=120)
    command_sync_wait_seconds: float = Field(default=3.0, ge=0.1, le=10)
    approval_ttl_seconds: int = Field(default=120, ge=5, le=120)
    state_sweep_interval_seconds: float = Field(default=1.0, ge=0.1, le=30)
    session_record_retention_days: int = Field(default=7, ge=1, le=90)
    device_pairing_retention_days: int = Field(default=7, ge=1, le=90)
    device_connection_retention_days: int = Field(default=30, ge=1, le=365)
    command_record_retention_days: int = Field(default=30, ge=1, le=365)
    approval_record_retention_days: int = Field(default=30, ge=1, le=365)
    thread_binding_retention_days: int = Field(default=90, ge=1, le=730)
    revoked_device_retention_days: int = Field(default=365, ge=30, le=3650)
    audit_event_retention_days: int = Field(default=365, ge=30, le=3650)
    retention_sweep_batch_size: int = Field(default=500, ge=1, le=5000)
    metrics_bearer_token: SecretStr = SecretStr(_DEVELOPMENT_METRICS_TOKEN)
    metrics_cache_seconds: float = Field(default=15.0, ge=1.0, le=300.0)
    metrics_query_timeout_seconds: float = Field(default=3.0, ge=0.1, le=30.0)

    @field_validator("api_prefix", "external_api_base_path", "sub2api_auth_me_path")
    @classmethod
    def validate_path_prefix(cls, value: str) -> str:
        normalized = value.rstrip("/") or "/"
        if not normalized.startswith("/"):
            raise ValueError("path prefixes must start with '/'")
        return normalized

    @field_validator("sub2api_base_url")
    @classmethod
    def validate_sub2api_url(cls, value: str) -> str:
        value = value.rstrip("/")
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("sub2api_base_url must be an http(s) URL")
        return value

    @field_validator("redis_prefix")
    @classmethod
    def validate_redis_prefix(cls, value: str) -> str:
        if not value or any(character.isspace() for character in value):
            raise ValueError("redis_prefix must be non-empty and contain no whitespace")
        return value

    @field_validator("session_hmac_secret")
    @classmethod
    def validate_session_secret(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().encode("utf-8")) < 32:
            raise ValueError("session_hmac_secret must contain at least 32 bytes")
        return value

    @field_validator("metrics_bearer_token")
    @classmethod
    def validate_metrics_token(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().encode("utf-8")) < 32:
            raise ValueError("metrics_bearer_token must contain at least 32 bytes")
        return value

    @model_validator(mode="after")
    def enforce_production_defaults(self) -> Settings:
        if self.owner_max_session_records < self.owner_max_active_sessions:
            raise ValueError(
                "CONTROL_OWNER_MAX_SESSION_RECORDS must be at least "
                "CONTROL_OWNER_MAX_ACTIVE_SESSIONS"
            )
        if self.owner_max_command_records < self.device_max_command_records:
            raise ValueError(
                "CONTROL_OWNER_MAX_COMMAND_RECORDS must be at least "
                "CONTROL_DEVICE_MAX_COMMAND_RECORDS"
            )
        if self.owner_max_thread_records < self.bootstrap_max_threads:
            raise ValueError(
                "CONTROL_OWNER_MAX_THREAD_RECORDS must be at least CONTROL_BOOTSTRAP_MAX_THREADS"
            )
        if self.device_max_approval_records < self.device_max_pending_approvals:
            raise ValueError(
                "CONTROL_DEVICE_MAX_APPROVAL_RECORDS must be at least "
                "CONTROL_DEVICE_MAX_PENDING_APPROVALS"
            )
        if self.owner_max_approval_records < self.bootstrap_max_pending_approvals:
            raise ValueError(
                "CONTROL_OWNER_MAX_APPROVAL_RECORDS must be at least "
                "CONTROL_BOOTSTRAP_MAX_PENDING_APPROVALS"
            )
        if self.browser_max_connections_per_user < self.browser_max_connections_per_session:
            raise ValueError(
                "CONTROL_BROWSER_MAX_CONNECTIONS_PER_USER must be at least "
                "CONTROL_BROWSER_MAX_CONNECTIONS_PER_SESSION"
            )
        if self.bootstrap_worst_case_bytes > self.bootstrap_max_response_bytes:
            raise ValueError(
                "configured bootstrap quotas can exceed CONTROL_BOOTSTRAP_MAX_RESPONSE_BYTES"
            )
        if self.environment != "production":
            return self
        if _is_known_insecure_secret(self.session_hmac_secret.get_secret_value()):
            raise ValueError(
                "CONTROL_SESSION_HMAC_SECRET must not use a known development, test, "
                "or example value in production"
            )
        if _is_known_insecure_secret(self.metrics_bearer_token.get_secret_value()):
            raise ValueError(
                "CONTROL_METRICS_BEARER_TOKEN must not use a known development, test, "
                "or example value in production"
            )
        if not self.cookie_secure:
            raise ValueError("secure cookies are required in production")
        if self.cookie_samesite != "strict":
            raise ValueError("SameSite=Strict cookies are required in production")
        if not self.cookie_name.startswith("__Host-"):
            raise ValueError("the production control cookie must use the __Host- prefix")
        if self.redis_url.startswith("memory://"):
            raise ValueError("the in-memory Redis backend is test-only")
        if not self.database_url.startswith("postgresql+"):
            raise ValueError("a PostgreSQL async database URL is required in production")
        if self.sub2api_base_url != _PRODUCTION_SUB2API_BASE_URL:
            raise ValueError(
                "CONTROL_SUB2API_BASE_URL must use the frozen internal Sub2API origin in production"
            )
        if self.sub2api_contract_marker != self.required_sub2api_contract_marker:
            raise ValueError(
                "CONTROL_SUB2API_CONTRACT_MARKER does not match the frozen Sub2API contract"
            )
        if not self.connector_release_ready:
            raise ValueError(
                "CONTROL_CONNECTOR_RELEASE_METADATA_JSON must contain the admitted "
                "Connector release in production"
            )
        if not self.allowed_origins:
            raise ValueError("at least one explicit allowed origin is required in production")
        if any(urlsplit(origin).scheme != "https" for origin in self.allowed_origins):
            raise ValueError("production allowed origins must use HTTPS")
        return self

    @property
    def bootstrap_worst_case_bytes(self) -> int:
        """Strict upper bound for the serialized ControlBootstrapResponse."""

        devices = self.bootstrap_max_devices * (
            BOOTSTRAP_DEVICE_SUMMARY_MAX_BYTES
            + BOOTSTRAP_MODEL_CATALOG_MAX_BYTES
            + BOOTSTRAP_MODEL_MAP_ENTRY_OVERHEAD_BYTES
        )
        threads = self.bootstrap_max_threads * (BOOTSTRAP_THREAD_SUMMARY_MAX_BYTES + 1)
        approvals = self.bootstrap_max_pending_approvals * (BOOTSTRAP_APPROVAL_ITEM_MAX_BYTES + 1)
        return (
            BOOTSTRAP_BASE_OVERHEAD_BYTES
            + BOOTSTRAP_CONNECTOR_RELEASE_MAX_BYTES
            + devices
            + threads
            + approvals
        )

    @property
    def allowed_origins(self) -> frozenset[str]:
        origins: set[str] = set()
        for raw_origin in self.allowed_origins_csv.split(","):
            origin = raw_origin.strip().rstrip("/")
            if not origin:
                continue
            parsed = urlsplit(origin)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"invalid allowed origin: {origin}")
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError(f"allowed origins cannot include a path: {origin}")
            origins.add(origin)
        return frozenset(origins)

    @property
    def pairing_poll_path_prefix(self) -> str:
        return f"{self.external_api_base_path}{self.api_prefix}"

    @property
    def required_sub2api_contract_marker(self) -> str:
        return f"{self.sub2api_expected_version}/{self.sub2api_expected_commit}"

    @property
    def sub2api_contract_ready(self) -> bool:
        if not self.sub2api_contract_marker:
            return self.environment != "production"
        return self.sub2api_contract_marker == self.required_sub2api_contract_marker

    @property
    def connector_release_ready(self) -> bool:
        if not self.connector_release_metadata_json.strip():
            return self.environment != "production"
        # Delayed import avoids the Settings/metadata-loader module cycle.
        from .connector_release import admitted_connector_release

        return admitted_connector_release(self) is not None


@lru_cache
def get_settings() -> Settings:
    return Settings()
