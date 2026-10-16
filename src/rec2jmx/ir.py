"""Format-neutral intermediate representation (IR).

Every parser converts its input into a :class:`Recording`. Everything downstream
(analysis, naming, generation) works only with these types. See docs/ARCHITECTURE.md
for the field-level contract.

Conventions:
* ``Request.path`` is the raw, percent-encoded path as sent on the wire (no query).
* ``Request.query`` / ``FormField`` values are *decoded* text.
* ``Response`` data is used only for analysis (correlation detection) and is never
  written to generated plans.
* Strings may contain JMeter expressions (``${name}``) when the source format had
  variables (JMX, Postman).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITIES = ("info", "warning", "error")


@dataclass
class Issue:
    """A message about something missing, discarded, changed, or suspicious."""

    severity: str  # "info" | "warning" | "error"
    code: str
    message: str
    request_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "requestId": self.request_id,
        }


@dataclass
class NameValue:
    name: str
    value: str


@dataclass
class QueryParam:
    name: str
    value: str
    has_equals: bool = True  # False for bare flags such as "?debug"


@dataclass
class FormField:
    name: str
    value: str = ""
    file_name: str | None = None  # set for multipart file parts (content is never available)
    content_type: str | None = None

    @property
    def is_file(self) -> bool:
        return self.file_name is not None


@dataclass
class Body:
    """Request body.

    kind:
      * ``none``      - no body
      * ``raw``       - ``text`` sent verbatim (JSON, XML, text, or raw multipart)
      * ``form``      - application/x-www-form-urlencoded ``fields``
      * ``multipart`` - multipart/form-data ``fields`` (JMeter builds the boundary)
    """

    kind: str = "none"
    text: str = ""
    content_type: str | None = None
    fields: list[FormField] = field(default_factory=list)


@dataclass
class Response:
    status: int | None = None
    headers: list[NameValue] = field(default_factory=list)
    body_text: str | None = None  # decoded text, truncated; analysis only
    content_type: str | None = None


@dataclass
class Request:
    id: str
    method: str
    scheme: str  # "http" | "https" ("" when unresolved_origin is set)
    host: str  # lower-case host, or a JMeter expression such as "${server}"
    port: int | None  # explicit port only; None means the scheme default
    path: str  # raw path starting with "/" (or a JMeter expression)
    query: list[QueryParam] = field(default_factory=list)
    headers: list[NameValue] = field(default_factory=list)
    body: Body = field(default_factory=Body)
    started_at: datetime | None = None
    duration_ms: float | None = None
    response: Response | None = None
    group_hint: str | None = None  # flow name suggested by the source (page, controller, folder)
    source_ref: str = ""  # location in the source, e.g. "log.entries[3]"
    resource_type: str | None = None  # e.g. HAR "_resourceType"
    unresolved_origin: str | None = None  # e.g. "${baseUrl}" when the origin is a variable

    @property
    def origin(self) -> str:
        if self.unresolved_origin:
            return self.unresolved_origin
        port = f":{self.port}" if self.port is not None else ""
        return f"{self.scheme}://{self.host}{port}"

    def header(self, name: str) -> str | None:
        lname = name.lower()
        for h in self.headers:
            if h.name.lower() == lname:
                return h.value
        return None


@dataclass
class Recording:
    source_format: str  # key in rec2jmx.formats.FORMATS
    source_name: str  # sanitized file name, display only
    requests: list[Request]
    issues: list[Issue] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)  # source-defined variable defaults
    grouping_source: str | None = None  # how group_hint was derived, e.g. "HAR pages"
    fingerprint: str = ""  # "sha256:<hex>" of the input bytes
    metadata: dict[str, Any] = field(default_factory=dict)

    def by_id(self) -> dict[str, Request]:
        return {r.id: r for r in self.requests}
