"""
Runtime context enrichment for U-HAP.

Converts raw request-time data (source IP, UTC hour) into semantic
classification values that ABAC predicates can evaluate against.

Public API:
  classify_ip(ip_str)    -> "on-premise" | "remote" | "vpn"
  classify_utc(hour)     -> "business-hours" | "after-hours"
  build_context(...)     -> merged context dict for evaluate()

Default network ranges (configurable via module-level constants):
  ON_PREMISE_CIDRS  - list of CIDR strings for on-premise networks
  VPN_CIDRS         - list of CIDR strings for VPN exit nodes
  Anything else     -> "remote"

Default business hours:
  BUSINESS_HOURS_START = 9   (9:00 UTC)
  BUSINESS_HOURS_END   = 17  (17:00 UTC, i.e., before 17:00)
"""

import ipaddress
from typing import Optional


# ---------------------------------------------------------------------------
# Configurable IP ranges
# ---------------------------------------------------------------------------

# On-premise: RFC-1918 private ranges used for internal corporate networks
ON_PREMISE_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# VPN exit nodes (example range; configure per deployment)
VPN_CIDRS = [
    "100.64.0.0/10",   # RFC 6598 shared address space, commonly used for VPNs
]


# ---------------------------------------------------------------------------
# Configurable business hours (UTC)
# ---------------------------------------------------------------------------

BUSINESS_HOURS_START = 9   # inclusive
BUSINESS_HOURS_END   = 17  # exclusive (before 17:00)


# ---------------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------------

# Pre-parse CIDR networks for performance (module-level)
_ON_PREMISE_NETS = [ipaddress.ip_network(c, strict=False) for c in ON_PREMISE_CIDRS]
_VPN_NETS        = [ipaddress.ip_network(c, strict=False) for c in VPN_CIDRS]


def classify_ip(ip_str: str) -> str:
    """Classify a source IP address into a network zone.

    Args:
        ip_str: IPv4 or IPv6 address string (e.g., "10.0.1.5", "1.2.3.4").
                If the string contains a comma (X-Forwarded-For list), the
                first (leftmost) address is used.

    Returns:
        "on-premise"  if the IP falls within ON_PREMISE_CIDRS
        "vpn"         if the IP falls within VPN_CIDRS
        "remote"      otherwise (public internet)

    Raises:
        ValueError if the IP string cannot be parsed (caller should handle)
    """
    # X-Forwarded-For may be "1.2.3.4, 5.6.7.8" — use the first (client) IP
    raw = ip_str.split(",")[0].strip()

    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        # Unknown / unparseable IP -> treat as remote (safe default)
        return "remote"

    for net in _ON_PREMISE_NETS:
        if addr in net:
            return "on-premise"

    for net in _VPN_NETS:
        if addr in net:
            return "vpn"

    return "remote"


# ---------------------------------------------------------------------------
# Time classification
# ---------------------------------------------------------------------------

def classify_utc(hour: int) -> str:
    """Classify a UTC hour into a time period.

    Args:
        hour: integer 0–23 representing the current UTC hour.

    Returns:
        "business-hours"  if BUSINESS_HOURS_START <= hour < BUSINESS_HOURS_END
        "after-hours"     otherwise
    """
    if BUSINESS_HOURS_START <= hour < BUSINESS_HOURS_END:
        return "business-hours"
    return "after-hours"


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def build_context(
    source_ip: str,
    utc_hour: int,
    token_attrs: Optional[dict] = None,
    extra_attrs: Optional[dict] = None,
) -> dict:
    """Build the merged context dict passed to evaluate().

    Merges runtime-derived values (network zone, time period) with
    attributes from the authentication token and any extra fields from
    the SAR 'extra' map.

    Precedence (lower overrides higher if same key):
        token_attrs -> extra_attrs -> runtime (net, time)

    Runtime values always win so that policy predicates can rely on
    server-side classification, not client-supplied values.

    Args:
        source_ip:   Raw source IP string from the request.
        utc_hour:    Current UTC hour (0–23).
        token_attrs: Optional dict of attributes from the auth token.
        extra_attrs: Optional dict from SAR spec.extra map.

    Returns:
        dict: merged context suitable for evaluate()
    """
    ctx: dict = {}

    # Start with token attributes (lowest priority)
    if token_attrs:
        ctx.update(token_attrs)

    # Extra SAR attributes
    if extra_attrs:
        ctx.update(extra_attrs)

    # Runtime-derived values (highest priority — cannot be spoofed by client)
    ctx["net"]  = classify_ip(source_ip)
    ctx["time"] = classify_utc(utc_hour)

    return ctx
