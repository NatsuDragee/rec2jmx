"""rec2jmx: convert recorded HTTP traffic and API test scenarios into Apache JMeter test plans.

The conversion engine (detection, parsers, analysis, naming, generation, validation)
has no user-interface code; the CLI (``rec2jmx.cli``) and local web UI
(``rec2jmx.web``) are thin layers over ``rec2jmx.service``.
"""

__version__ = "0.1.0"
