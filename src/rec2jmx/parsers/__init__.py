"""Format-specific parsers. Each returns a ParseResult built from IR types."""

from .curl import parse_curl
from .har import parse_har
from .jmx import parse_jmx
from .native_json import parse_native_json
from .postman import parse_postman

PARSERS = {
    "har": parse_har,
    "curl": parse_curl,
    "jmx": parse_jmx,
    "postman": parse_postman,
    "rec2jmx-json": parse_native_json,
}

__all__ = ["PARSERS"]
