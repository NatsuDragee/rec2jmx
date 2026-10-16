"""Classify well-known third-party hosts so users can exclude them quickly.

Classification never excludes anything by itself; it only labels hosts in the preview.
"""

from __future__ import annotations

# category -> registrable domains (a host matches the domain itself or any subdomain)
_KNOWN: dict[str, tuple[str, ...]] = {
    "analytics": (
        "google-analytics.com", "analytics.google.com", "googletagmanager.com", "doubleclick.net",
        "googleadservices.com", "segment.io", "segment.com", "mixpanel.com", "amplitude.com", "hotjar.com",
        "hotjar.io", "clarity.ms", "fullstory.com", "heap.io", "heapanalytics.com", "facebook.net",
        "bat.bing.com", "snap.licdn.com", "px.ads.linkedin.com", "plausible.io", "quantserve.com",
        "scorecardresearch.com", "adobedtm.com", "omtrdc.net", "demdex.net", "matomo.cloud",
    ),
    "monitoring": (
        "nr-data.net", "newrelic.com", "sentry.io", "datadoghq.com", "datadoghq.eu",
        "browser-intake-datadoghq.com", "dynatrace.com", "appdynamics.com", "eum-appdynamics.com",
        "bugsnag.com", "rollbar.com", "logrocket.io", "lr-ingest.io", "raygun.io",
        "cloudflareinsights.com", "speedcurve.com",
    ),
    "feature flags": (
        "growthbook.io", "launchdarkly.com", "optimizely.com", "split.io", "statsig.com", "configcat.com",
    ),
    "chat/support": (
        "pure.cloud", "mypurecloud.com", "intercom.io", "intercomcdn.com", "zendesk.com", "zopim.com",
        "drift.com", "livechatinc.com", "tawk.to", "freshchat.com", "hubspot.com",
    ),
    "identity": (
        "identitytoolkit.googleapis.com", "securetoken.googleapis.com", "auth0.com", "okta.com",
        "login.microsoftonline.com", "cognito-idp.amazonaws.com",
    ),
}

# Categories that are usually safe to leave out of a load test of your own application.
EXCLUDABLE = ("analytics", "monitoring", "feature flags", "chat/support")


def classify_host(host: str) -> str | None:
    h = host.lower().rstrip(".")
    for category, domains in _KNOWN.items():
        for d in domains:
            if h == d or h.endswith("." + d):
                return category
    return None
