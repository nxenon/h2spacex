"""
Tests for h2spacex.utils (pure-stdlib header helpers).

These import the installed package when available, and fall back to loading
utils.py directly from source so the suite also runs without the heavier
runtime dependencies (scapy/brotli) installed.
"""
import importlib.util
import os

try:
    from h2spacex import utils
except Exception:  # pragma: no cover - fallback for minimal environments
    _utils_path = os.path.join(
        os.path.dirname(__file__), "..", "src", "h2spacex", "utils.py"
    )
    _spec = importlib.util.spec_from_file_location("h2spacex_utils", _utils_path)
    utils = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(utils)


def test_make_header_names_small_lowercases_names_preserves_values():
    result = utils.make_header_names_small("User-Agent: Test\nACCEPT: */*")
    assert result == "user-agent: Test\naccept: */*"


def test_make_header_names_small_strips_surrounding_whitespace():
    assert utils.make_header_names_small("  Content-Type: text/html  ") == "content-type: text/html"


def test_make_header_names_small_is_idempotent():
    once = utils.make_header_names_small("X-Custom-Header: KeepCase")
    twice = utils.make_header_names_small(once)
    assert once == twice == "x-custom-header: KeepCase"


def test_convert_request_headers_dict_to_string():
    result = utils.convert_request_headers_dict_to_string(
        {"User-Agent": "x", "Accept": "*/*"}
    )
    assert result == "user-agent: x\naccept: */*\n"


def test_convert_request_headers_dict_to_string_empty():
    assert utils.convert_request_headers_dict_to_string({}) == ""


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("All tests passed.")
