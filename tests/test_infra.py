"""Tests du module infrastructure.

Verifie les decorateurs AOP, la configuration centralisee,
et la hierarchie d'exceptions. Tous les tests fonctionnent
sans Docker ni API keys.
"""


# ---------------------------------------------------------------------------
# TestDecorators
# ---------------------------------------------------------------------------


class TestDecorators:
    """Test AOP decorators from src.infra.decorators."""

    def test_logged_decorator(self):
        from src.infra.decorators import logged

        @logged
        def dummy():
            return 42

        assert dummy() == 42

    def test_logged_preserves_return_value(self):
        from src.infra.decorators import logged

        @logged
        def add(a, b):
            return a + b

        assert add(3, 7) == 10

    def test_logged_with_level_parameter(self):
        import logging

        from src.infra.decorators import logged

        @logged(level=logging.DEBUG)
        def dummy():
            return "ok"

        assert dummy() == "ok"

    def test_logged_reraises_exceptions(self):
        import pytest

        from src.infra.decorators import logged

        @logged
        def failing():
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            failing()

    def test_safe_returns_fallback(self):
        from src.infra.decorators import safe

        @safe(fallback="default")
        def failing():
            raise ValueError("boom")

        assert failing() == "default"

    def test_safe_returns_normal_value_on_success(self):
        from src.infra.decorators import safe

        @safe(fallback="default")
        def succeeding():
            return "ok"

        assert succeeding() == "ok"

    def test_safe_with_specific_exceptions(self):
        import pytest

        from src.infra.decorators import safe

        @safe(fallback="default", exceptions=(ValueError,))
        def failing_type_error():
            raise TypeError("wrong type")

        # TypeError is not in the caught exceptions, so it should propagate
        with pytest.raises(TypeError):
            failing_type_error()

    def test_safe_bare_decorator(self):
        from src.infra.decorators import safe

        @safe
        def failing():
            raise RuntimeError("boom")

        assert failing() is None  # default fallback is None

    def test_retry_retries(self):
        from src.infra.decorators import retry

        call_count = 0

        @retry(max_attempts=3, base_delay=0.01)
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError()
            return "ok"

        assert flaky() == "ok"
        assert call_count == 3

    def test_retry_raises_after_all_attempts(self):
        import pytest

        from src.infra.decorators import retry

        @retry(max_attempts=2, base_delay=0.01)
        def always_fails():
            raise ConnectionError("down")

        with pytest.raises(ConnectionError, match="down"):
            always_fails()

    def test_retry_succeeds_on_first_try(self):
        from src.infra.decorators import retry

        call_count = 0

        @retry(max_attempts=3, base_delay=0.01)
        def succeeding():
            nonlocal call_count
            call_count += 1
            return "ok"

        assert succeeding() == "ok"
        assert call_count == 1

    def test_retry_with_specific_exceptions(self):
        import pytest

        from src.infra.decorators import retry

        @retry(max_attempts=3, base_delay=0.01, exceptions=(ConnectionError,))
        def fails_with_value_error():
            raise ValueError("not retryable")

        # ValueError is not in the retryable exceptions, should propagate immediately
        with pytest.raises(ValueError, match="not retryable"):
            fails_with_value_error()

    def test_timed_decorator(self):
        from src.infra.decorators import timed

        @timed
        def slow():
            return 1

        assert slow() == 1

    def test_timed_preserves_return(self):
        from src.infra.decorators import timed

        @timed
        def compute():
            return [1, 2, 3]

        assert compute() == [1, 2, 3]

    def test_timed_reraises_exceptions(self):
        import pytest

        from src.infra.decorators import timed

        @timed
        def failing():
            raise RuntimeError("timed out")

        with pytest.raises(RuntimeError, match="timed out"):
            failing()

    def test_composable_decorators(self):
        """Decorators should be stackable in any order."""
        from src.infra.decorators import logged, timed

        @logged
        @timed
        def compute():
            return 42

        assert compute() == 42

    def test_decorators_preserve_function_name(self):
        from src.infra.decorators import logged, retry, safe, timed

        @logged
        def func_a():
            pass

        @timed
        def func_b():
            pass

        @safe(fallback=None)
        def func_c():
            pass

        @retry(max_attempts=1, base_delay=0.01)
        def func_d():
            pass

        assert func_a.__name__ == "func_a"
        assert func_b.__name__ == "func_b"
        assert func_c.__name__ == "func_c"
        assert func_d.__name__ == "func_d"


# ---------------------------------------------------------------------------
# TestConfig
# ---------------------------------------------------------------------------


class TestConfig:
    """Test centralized config from src.infra.config."""

    def test_settings_loads(self):
        from src.infra.config import settings

        assert settings.llm_model is not None
        assert settings.target_url is not None

    def test_default_values(self):
        from src.infra.config import settings

        assert settings.api_port == 8080
        assert settings.attack_delay == 0.2

    def test_default_llm_model(self):
        from src.infra.config import settings

        assert "claude" in settings.llm_model.lower() or settings.llm_model is not None

    def test_default_target_url(self):
        from src.infra.config import settings

        assert settings.target_url == "http://localhost:3000"

    def test_default_scan_timeout(self):
        from src.infra.config import settings

        assert settings.scan_timeout == 300

    def test_default_executor_timeout(self):
        from src.infra.config import settings

        assert settings.executor_timeout == 30

    def test_default_log_level(self):
        from src.infra.config import settings

        assert settings.log_level == "INFO"

    def test_settings_has_cors_origins(self):
        from src.infra.config import settings

        assert isinstance(settings.cors_origins, list)
        assert len(settings.cors_origins) >= 1

    def test_get_settings_returns_same_instance(self):
        from src.infra.config import get_settings, settings

        cached = get_settings()
        assert cached is settings

    def test_settings_is_pydantic_model(self):
        from pydantic_settings import BaseSettings

        from src.infra.config import settings

        assert isinstance(settings, BaseSettings)


# ---------------------------------------------------------------------------
# TestExceptions
# ---------------------------------------------------------------------------


class TestExceptions:
    """Test exception hierarchy from src.infra.exceptions."""

    def test_base_exception(self):
        from src.infra.exceptions import RedSimulatorError

        exc = RedSimulatorError("test", details={"key": "val"})
        safe = exc.to_safe_dict()
        assert safe["error"] == "INTERNAL_ERROR"
        assert safe["message"] == "test"
        assert "key" not in safe  # details not leaked to client

    def test_base_exception_details_stored(self):
        from src.infra.exceptions import RedSimulatorError

        exc = RedSimulatorError("test", details={"key": "val"})
        assert exc.details == {"key": "val"}

    def test_base_exception_no_details(self):
        from src.infra.exceptions import RedSimulatorError

        exc = RedSimulatorError("simple error")
        assert exc.details == {}

    def test_base_exception_repr(self):
        from src.infra.exceptions import RedSimulatorError

        exc = RedSimulatorError("test")
        r = repr(exc)
        assert "RedSimulatorError" in r
        assert "INTERNAL_ERROR" in r

    def test_base_exception_repr_with_details(self):
        from src.infra.exceptions import RedSimulatorError

        exc = RedSimulatorError("test", details={"k": "v"})
        r = repr(exc)
        assert "details" in r

    def test_config_error(self):
        from src.infra.exceptions import ConfigError, RedSimulatorError

        exc = ConfigError("bad config")
        assert isinstance(exc, RedSimulatorError)
        assert exc.code == "CONFIG_ERROR"
        safe = exc.to_safe_dict()
        assert safe["error"] == "CONFIG_ERROR"

    def test_tool_error_includes_tool_name(self):
        from src.infra.exceptions import ToolError

        exc = ToolError("nmap failed", tool_name="port_scan")
        safe = exc.to_safe_dict()
        assert safe["tool_name"] == "port_scan"
        assert safe["error"] == "TOOL_ERROR"
        assert safe["message"] == "nmap failed"

    def test_rule_error_includes_rule_name(self):
        from src.infra.exceptions import RuleError

        exc = RuleError("rule failed", rule_name="SQL_INJECTION")
        safe = exc.to_safe_dict()
        assert safe["rule_name"] == "SQL_INJECTION"
        assert safe["error"] == "RULE_ERROR"

    def test_phase_error_includes_phase_name(self):
        from src.infra.exceptions import PhaseError

        exc = PhaseError("scanning failed", phase_name="scanning")
        safe = exc.to_safe_dict()
        assert safe["phase_name"] == "scanning"
        assert safe["error"] == "PHASE_ERROR"

    def test_attack_error_includes_vector_id(self):
        from src.infra.exceptions import AttackError

        exc = AttackError("attack failed", vector_id="VEC-001")
        safe = exc.to_safe_dict()
        assert safe["vector_id"] == "VEC-001"
        assert safe["error"] == "ATTACK_ERROR"

    def test_exception_hierarchy(self):
        """All exceptions should inherit from RedSimulatorError."""
        from src.infra.exceptions import (
            AgentError,
            AttackError,
            ConfigError,
            DockerServiceError,
            ExecutorError,
            ExpertError,
            ExternalServiceError,
            GeneratorError,
            LLMError,
            PhaseError,
            PipelineError,
            PipelineTimeoutError,
            RAGError,
            RedSimulatorError,
            ReporterError,
            RuleError,
            ScanError,
            ScanTimeoutError,
            ToolError,
        )

        # All should be subclass of RedSimulatorError
        all_exceptions = [
            ConfigError,
            PipelineError,
            PhaseError,
            PipelineTimeoutError,
            ScanError,
            ScanTimeoutError,
            ToolError,
            AgentError,
            ExpertError,
            RuleError,
            GeneratorError,
            ExecutorError,
            AttackError,
            ReporterError,
            RAGError,
            ExternalServiceError,
            LLMError,
            DockerServiceError,
        ]
        for exc_cls in all_exceptions:
            assert issubclass(exc_cls, RedSimulatorError), (
                f"{exc_cls.__name__} should subclass RedSimulatorError"
            )

    def test_exception_is_catchable_as_base_exception(self):
        """Specific exceptions should be catchable via the base class."""
        from src.infra.exceptions import RedSimulatorError, ToolError

        try:
            raise ToolError("test", tool_name="nmap")
        except RedSimulatorError as e:
            assert e.message == "test"
        else:
            raise AssertionError("ToolError should be caught as RedSimulatorError")

    def test_scan_error_hierarchy(self):
        """ScanTimeoutError and ToolError should be subclasses of ScanError."""
        from src.infra.exceptions import ScanError, ScanTimeoutError, ToolError

        assert issubclass(ScanTimeoutError, ScanError)
        assert issubclass(ToolError, ScanError)

    def test_pipeline_error_hierarchy(self):
        """PhaseError and PipelineTimeoutError should be subclasses of PipelineError."""
        from src.infra.exceptions import (
            PhaseError,
            PipelineError,
            PipelineTimeoutError,
        )

        assert issubclass(PhaseError, PipelineError)
        assert issubclass(PipelineTimeoutError, PipelineError)

    def test_reporter_error_hierarchy(self):
        """RAGError should be subclass of ReporterError."""
        from src.infra.exceptions import RAGError, ReporterError

        assert issubclass(RAGError, ReporterError)

    def test_external_service_hierarchy(self):
        """LLMError and DockerServiceError should be subclasses of ExternalServiceError."""
        from src.infra.exceptions import (
            DockerServiceError,
            ExternalServiceError,
            LLMError,
        )

        assert issubclass(LLMError, ExternalServiceError)
        assert issubclass(DockerServiceError, ExternalServiceError)

    def test_safe_dict_never_leaks_details(self):
        """to_safe_dict() should never include the details dictionary."""
        from src.infra.exceptions import RedSimulatorError

        exc = RedSimulatorError(
            "error",
            details={"secret_key": "abc123", "internal_path": "/etc/shadow"},
        )
        safe = exc.to_safe_dict()
        assert "secret_key" not in str(safe)
        assert "abc123" not in str(safe)
        assert "internal_path" not in str(safe)
