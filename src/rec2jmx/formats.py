"""The authoritative list of supported input formats and their known limitations.

Keep this in sync with docs/FORMATS.md. A format appears here only when a parser
and tests exist for it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FormatInfo:
    key: str
    label: str
    extensions: tuple[str, ...]
    limitations: tuple[str, ...]


GENERAL_LIMITATIONS = (
    "JMeter replays HTTP(S) requests only. Mobile (Android/iOS) and browser UI interactions "
    "are not replayed; plans generated from mobile captures test the captured API traffic, "
    "not the app's UI behaviour.",
    "Correlations are suggestions inferred from recorded responses. Review them; business "
    "logic, conditional flows, and dynamic values without a recorded source are not inferred.",
    "Recorded request headers are kept as recorded (including Cookie). JMeter's HTTP Cookie "
    "Manager replaces a recorded Cookie header once it holds cookies for that URL.",
    "WebSocket, gRPC, HTTP/2 server push, and non-HTTP traffic are not converted.",
)

FORMATS: dict[str, FormatInfo] = {
    "har": FormatInfo(
        key="har",
        label="HAR (HTTP Archive) 1.1/1.2",
        extensions=(".har",),
        limitations=(
            "Static resources (images, CSS, JS, fonts, media) are excluded by default "
            "(use --include-static to keep them).",
            "Multipart file contents are usually absent from HAR files; file parts need a "
            "local file supplied via the FILE_DIR variable.",
            "WebSocket entries and non-HTTP(S) URLs are skipped.",
            "Flows are grouped by HAR pages when present, otherwise by time gaps (heuristic).",
        ),
    ),
    "curl": FormatInfo(
        key="curl",
        label="cURL command(s) (bash or Windows cmd syntax)",
        extensions=(".curl", ".sh", ".txt"),
        limitations=(
            "Only a subset of curl options is understood; other options are reported and ignored.",
            "Shell features (variables, pipes, command substitution) are not evaluated.",
            "@file data/form references are not read; the file must be supplied separately.",
            "No timing or response data is available, so no correlations can be suggested.",
            "Use '# flow: <name>' comment lines to group commands into flows.",
        ),
    ),
    "jmx": FormatInfo(
        key="jmx",
        label="Apache JMeter test plan (.jmx)",
        extensions=(".jmx",),
        limitations=(
            "Only HTTP Request samplers, Header Managers, HTTP Request Defaults, User Defined "
            "Variables and Transaction Controllers are converted.",
            "Extractors, assertions, timers, scripts and other samplers are not carried over "
            "(reported as warnings). Logic controllers are flattened in order.",
            "Disabled elements are skipped.",
        ),
    ),
    "postman": FormatInfo(
        key="postman",
        label="Postman Collection v2.0/v2.1",
        extensions=(".json",),
        limitations=(
            "Pre-request and test scripts are not converted or executed.",
            "Auth types other than bearer, basic, and API key are not converted.",
            "Environment files are not read; collection variables are inlined and unknown "
            "variables become JMeter properties (-Jname=value).",
            "No timing or response data, so no correlations can be suggested.",
        ),
    ),
    "rec2jmx-json": FormatInfo(
        key="rec2jmx-json",
        label="rec2jmx JSON recording v1 (documented schema)",
        extensions=(".json",),
        limitations=(
            "Must follow the schema in docs/FORMATS.md; binary bodies are not supported.",
        ),
    ),
}

EXTENSION_HINTS = {".har": "har", ".jmx": "jmx", ".curl": "curl"}
