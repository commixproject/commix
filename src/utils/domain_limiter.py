#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2024 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

"""
Domain / scope limiting helper.

Intended location: src/utils/domain_limiter.py

Provides helpers to:
  * Normalize hostnames from URLs or raw hosts.
  * Keep a whitelist / blacklist of domains.
  * Decide whether a given URL / host is in-scope.

Typical usage inside Commix:

    from src.utils.domain_limiter import DomainScopeLimiter

    limiter = DomainScopeLimiter(
        allowed_domains=["example.com"],
        blocked_domains=["admin.example.com"],
        include_subdomains=True
    )

    if limiter.is_in_scope(target_url):
        # proceed with request / crawling
        pass
    else:
        # skip
        pass
"""

import re

try:
    # Commix-style imports (if running inside the project)
    from src.thirdparty.six.moves import urllib as _urllib  # type: ignore
    from src.utils import settings
except ImportError:  # pragma: no cover - makes the module usable standalone
    import urllib as _urllib  # type: ignore
    settings = None  # type: ignore


def _debug(message):
    """
    Internal debug printing helper.

    Uses Commix settings if available, otherwise falls back to plain print.
    """
    if settings is not None:
        try:
            settings.print_debug_msg(str(message))
            return
        except Exception:
            # Fall back to simple print if something unexpected happens
            pass

    # Fallback for standalone usage or if settings is not available
    print("[domain_limiter] %s" % message)


def _extract_hostname(url_or_host):
    """
    Extract hostname from a URL or return the host as-is.

    Accepts:
      * Full URL:  http://www.example.com/path?param=1
      * Host only: www.example.com
      * Host:port: www.example.com:8080

    Returns a lowercase hostname without port, or None if it cannot be parsed.
    """
    if not url_or_host:
        return None

    text = url_or_host.strip()

    # Heuristic: if it looks like a URL (has scheme://), use urlparse
    if "://" in text:
        try:
            parsed = _urllib.parse.urlparse(text)
            host = parsed.hostname
        except Exception:
            host = None
    else:
        # Treat as host[:port] or raw IP
        host = text.split("/", 1)[0]
        if ":" in host and not host.startswith("["):  # basic IPv6 exclusion
            host = host.split(":", 1)[0]

    if not host:
        return None

    host = host.strip().lower().rstrip(".")

    if not host:
        return None

    # Normalize punycode if present
    try:
        host = host.encode("ascii").decode("idna")
    except Exception:
        # If it's not ASCII/punycode, keep as-is
        pass

    return host


def _normalize_pattern(pattern):
    """
    Normalize a domain pattern for matching.

    Examples:
      "EXAMPLE.com." -> "example.com"
      "  *.example.com  " -> "example.com" (leading * and dot removed)
    """
    if not pattern:
        return None

    p = pattern.strip().lower().rstrip(".")

    # Optional wildcard prefix like *.example.com
    if p.startswith("*."):
        p = p[2:]

    return p or None


def _host_matches_pattern(host, pattern, include_subdomains=True):
    """
    Check if a hostname matches a pattern.

    host / pattern are expected to be normalized (lowercase, no trailing dot).

    include_subdomains:
      * True  -> "sub.example.com" matches pattern "example.com".
      * False -> only exact match ("example.com" == "example.com").
    """
    if not host or not pattern:
        return False

    if host == pattern:
        return True

    if include_subdomains and host.endswith("." + pattern):
        return True

    return False


class DomainScopeLimiter(object):
    """
    Domain scope limiter for HTTP requests / crawling.

    Parameters
    ----------
    allowed_domains : list[str] or None
        If not empty, only these domains (and optionally their subdomains)
        are considered in-scope. If None or empty, everything is allowed
        unless explicitly blocked.

    blocked_domains : list[str] or None
        Domains (or patterns) that should always be treated as out-of-scope.

    include_subdomains : bool
        If True, subdomains of allowed_domains are also in-scope.
        Example:
          allowed: example.com
          include_subdomains=True
          host:   api.example.com   -> allowed
    """

    def __init__(self, allowed_domains=None, blocked_domains=None,
                 include_subdomains=True):
        self.include_subdomains = bool(include_subdomains)

        self.allowed_patterns = self._prepare_patterns(allowed_domains or [])
        self.blocked_patterns = self._prepare_patterns(blocked_domains or [])

        _debug(
            "Initialized DomainScopeLimiter "
            "(allowed=%r, blocked=%r, include_subdomains=%r)"
            % (self.allowed_patterns,
               self.blocked_patterns,
               self.include_subdomains)
        )

    @staticmethod
    def _prepare_patterns(patterns):
        """
        Normalize domain patterns and deduplicate them.
        """
        result = set()
        for p in patterns:
            normalized = _normalize_pattern(p)
            if normalized:
                result.add(normalized)
        return sorted(result)

    def add_allowed(self, pattern):
        """
        Dynamically add a new allowed domain pattern.
        """
        normalized = _normalize_pattern(pattern)
        if not normalized:
            return
        if normalized not in self.allowed_patterns:
            self.allowed_patterns.append(normalized)

    def add_blocked(self, pattern):
        """
        Dynamically add a new blocked domain pattern.
        """
        normalized = _normalize_pattern(pattern)
        if not normalized:
            return
        if normalized not in self.blocked_patterns:
            self.blocked_patterns.append(normalized)

    def is_in_scope(self, url_or_host):
        """
        Main check: returns True if the given URL / host is in-scope.

        Logic:
          1. Extract and normalize hostname.
          2. If host matches any blocked domain -> False.
          3. If allowed list is empty           -> True (no positive restriction).
          4. Otherwise host must match an allowed pattern.
        """
        host = _extract_hostname(url_or_host)

        if not host:
            # If we cannot parse a host, treat as out-of-scope
            _debug("Unable to extract hostname from: %r" % url_or_host)
            return False

        # 1) Explicitly blocked domains win
        for pattern in self.blocked_patterns:
            if _host_matches_pattern(host, pattern, include_subdomains=True):
                _debug("Host %r is blocked by pattern %r" % (host, pattern))
                return False

        # 2) If there is no allow-list, everything (not blocked) is in-scope
        if not self.allowed_patterns:
            _debug("No allowed_domains configured, %r considered in-scope" % host)
            return True

        # 3) Check against allowed patterns
        for pattern in self.allowed_patterns:
            if _host_matches_pattern(host, pattern, self.include_subdomains):
                _debug("Host %r is allowed by pattern %r" % (host, pattern))
                return True

        _debug("Host %r is NOT allowed by any pattern" % host)
        return False

    def filter_urls(self, urls):
        """
        Convenience helper: filter a sequence of URLs / hosts,
        returning only those that are in-scope.
        """
        for u in urls:
            if self.is_in_scope(u):
                yield u


if __name__ == "__main__":  # pragma: no cover
    # Simple manual test for standalone usage.
    limiter = DomainScopeLimiter(
        allowed_domains=["example.com"],
        blocked_domains=["admin.example.com"],
        include_subdomains=True
    )

    tests = [
        "http://example.com/",
        "http://sub.example.com/path",
        "https://admin.example.com/panel",
        "https://other.com/",
        "example.com:8080",
        "sub.other.com",
    ]

    for t in tests:
        print("%-35s -> %s" % (t, limiter.is_in_scope(t)))
