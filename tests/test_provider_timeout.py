"""Per-provider request-timeout selection (before the env override).

Heavy local reasoning MoEs emit long single turns; the generic API_TIMEOUT cut
``ollama-umons`` graph turns mid-generation, so that provider gets a wider
default, keyed by name like ``local-moe`` already is.
"""
from src.config import API_TIMEOUT
from src.agent.core.provider_transport import is_timeout_error
from src.agent.provider import (
    _LOCAL_MOE_API_TIMEOUT,
    _OLLAMA_UMONS_API_TIMEOUT,
    _request_timeout_for,
)


def test_local_moe_keeps_its_own_timeout():
    assert _request_timeout_for("local-moe") == _LOCAL_MOE_API_TIMEOUT


def test_ollama_umons_gets_its_own_timeout():
    assert _request_timeout_for("ollama-umons") == _OLLAMA_UMONS_API_TIMEOUT


def test_other_providers_fall_back_to_generic_timeout():
    assert _request_timeout_for("minimax") == API_TIMEOUT
    assert _request_timeout_for("some-unknown-provider") == API_TIMEOUT


def test_ollama_umons_default_is_wider_than_generic():
    # The whole point of the change: the generic 120s cut flint's graph turn.
    assert _OLLAMA_UMONS_API_TIMEOUT > API_TIMEOUT


def test_is_timeout_error_matches_builtin_and_sdk_timeout_names():
    class APITimeoutError(Exception):
        pass

    class ReadTimeout(Exception):
        pass

    assert is_timeout_error(TimeoutError("read timed out")) is True
    assert is_timeout_error(APITimeoutError("Request timed out.")) is True
    assert is_timeout_error(ReadTimeout("timed out")) is True
    assert is_timeout_error(ConnectionError("reset")) is False
    assert is_timeout_error(ValueError("bad request")) is False
