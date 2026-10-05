#!/usr/bin/env python3
"""
ColdEngine OS v1.2.1
B2B Lead Intelligence Pre-Flight Engine

Pure Python standard library.
Zero external dependencies.
"""

import argparse
import csv
import ipaddress
import json
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request


VERSION = "1.2.1"
USER_AGENT = f"ColdEngine-OS/{VERSION} (Pre-Flight Engine)"


def sanitize_domain(raw_input: str) -> str:
    """Extract and validate a clean hostname."""

    if not isinstance(raw_input, str):
        return ""

    raw = raw_input.strip().lower()

    if not raw:
        return ""

    if raw.startswith("//"):
        raw = "https:" + raw
    elif "://" not in raw:
        raw = "https://" + raw

    try:
        parsed = urllib.parse.urlparse(raw)
        hostname = parsed.hostname
    except ValueError:
        return ""

    if not hostname:
        return ""

    hostname = hostname.rstrip(".").lower()

    try:
        ipaddress.ip_address(hostname)
        return ""
    except ValueError:
        pass

    if hostname in {"localhost", "localhost.localdomain"}:
        return ""

    if len(hostname) > 253:
        return ""

    labels = hostname.split(".")

    if len(labels) < 2:
        return ""

    label_pattern = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    for label in labels:
        if not label or len(label) > 63:
            return ""

        if not label_pattern.fullmatch(label):
            return ""

    return hostname


class ColdEngine:

    def __init__(
        self,
        raw_domain: str,
        first_name: str = "",
        last_name: str = "",
        company: str = "",
    ):
        self.domain = sanitize_domain(raw_domain)

        self.first_name = self._clean_name(first_name)
        self.last_name = self._clean_name(last_name)

        self.company = company.strip()

        if not self.company and self.domain:
            self.company =
