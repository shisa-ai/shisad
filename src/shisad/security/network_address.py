"""Canonical network-address and bounded local-host classification."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from shisad.core.url_parsing import canonicalize_url_host


@dataclass(frozen=True, slots=True)
class NetworkAddress:
    """Typed address facts shared by network policy consumers."""

    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    canonical: str
    is_public: bool
    is_loopback: bool


def classify_network_address(value: str) -> NetworkAddress | None:
    """Classify standard or supported legacy numeric address syntax."""

    host = canonicalize_url_host(value)
    if not host:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if ":" in host:
            return None
        try:
            address = ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None

    mapped = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    is_loopback = bool(address.is_loopback or (mapped is not None and mapped.is_loopback))
    is_site_local = bool(isinstance(address, ipaddress.IPv6Address) and address.is_site_local)
    return NetworkAddress(
        address=address,
        canonical=address.compressed,
        is_public=bool(address.is_global and not address.is_multicast and not is_site_local),
        is_loopback=is_loopback,
    )


def is_ip_literal(value: str) -> bool:
    """Return whether ``value`` is standard or supported legacy IP syntax."""

    return classify_network_address(value) is not None


def is_private_or_special_address(value: str) -> bool:
    """Return whether a valid address is not globally routable unicast."""

    classified = classify_network_address(value)
    return classified is not None and not classified.is_public


def is_local_hostname(value: str) -> bool:
    """Recognize the bounded reserved/baseline local-name set."""

    host = canonicalize_url_host(value)
    if not host:
        return False
    return host == "localhost" or host.endswith(
        (".localhost", ".local", ".internal", ".lan"),
    )


def is_loopback_host(value: str) -> bool:
    """Return whether a host is reserved localhost or numeric loopback."""

    host = canonicalize_url_host(value)
    if host == "localhost" or host.endswith(".localhost"):
        return True
    classified = classify_network_address(host)
    return classified is not None and classified.is_loopback
