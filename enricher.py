#!/usr/bin/env python3
"""
ColdEngine OS (v1.2.1)
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
    """
    Extract and validate a clean hostname from:
      - example.com
      - https://example.com/path
      - https://example.com:443/path
      - //example.com/path

    Rejects malformed hosts, IP addresses, localhost and hostnames
    containing invalid characters.
    """
    if not isinstance(raw_input, str):
        return ""

    raw = raw_input.strip().lower()

    if not raw:
        return ""

    # Handle protocol-relative URLs.
    if raw.startswith("//"):
        raw = "https:" + raw

    # Treat bare domains as URLs.
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

    # Reject IP addresses.
    try:
        ipaddress.ip_address(hostname)
        return ""
    except ValueError:
        pass

    # Reject localhost / local names.
    if hostname in {"localhost", "localhost.localdomain"}:
        return ""

    # Basic hostname validation.
    if len(hostname) > 253:
        return ""

    labels = hostname.split(".")

    # B2B root domains should contain at least one dot.
    if len(labels) < 2:
        return ""

    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

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
            self.company = self.domain.split(".")[0].capitalize()

    @staticmethod
    def _clean_name(value: str) -> str:
        """Normalize names for deterministic email candidate generation."""
        if not isinstance(value, str):
            return ""

        value = value.strip().lower()

        # Keep letters/numbers only for email candidates.
        return re.sub(r"[^a-z0-9]", "", value)

    def check_mx_records(self) -> dict:
        """
        Query Google DNS-over-HTTPS for MX records.

        Returns explicit states for:
          - VALID_MAIL_EXCHANGE
          - NXDOMAIN
          - NO_MX_RECORDS
          - NULL_MX_EXPLICIT_REJECT
          - retryable network failures
          - malformed DNS responses
        """

        if not self.domain:
            return {
                "status": "INVALID_DOMAIN_FORMAT",
                "has_mx": False,
                "retryable": False,
                "mx_records": [],
            }

        doh_url = (
            "https://dns.google/resolve?"
            f"name={urllib.parse.quote(self.domain)}&type=MX"
        )

        request = urllib.request.Request(
            doh_url,
            headers={"User-Agent": USER_AGENT},
        )

        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                raw_body = response.read().decode("utf-8")

            data = json.loads(raw_body)

        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            return {
                "status": f"DNS_LOOKUP_ERROR: {type(exc).__name__}",
                "has_mx": None,
                "retryable": True,
                "mx_records": [],
            }

        except json.JSONDecodeError:
            return {
                "status": "DNS_INVALID_JSON",
                "has_mx": None,
                "retryable": True,
                "mx_records": [],
            }

        status_code = data.get("Status")

        if not isinstance(status_code, int):
            return {
                "status": "DNS_INVALID_RESPONSE",
                "has_mx": None,
                "retryable": True,
                "mx_records": [],
            }

        # RCODE 3 = NXDOMAIN.
        if status_code == 3:
            return {
                "status": "NXDOMAIN",
                "has_mx": False,
                "retryable": False,
                "mx_records": [],
            }

        # RCODE 0 = NOERROR.
        if status_code == 0:
            answers = data.get("Answer", [])

            if not isinstance(answers, list):
                return {
                    "status": "DNS_INVALID_ANSWER",
                    "has_mx": None,
                    "retryable": True,
                    "mx_records": [],
                }

            if not answers:
                return {
                    "status": "NO_MX_RECORDS",
                    "has_mx": False,
                    "retryable": False,
                    "mx_records": [],
                }

            mx_hosts = []

            for answer in answers:
                if not isinstance(answer, dict):
                    continue

                record_data = answer.get("data", "")

                if not isinstance(record_data, str):
                    continue

                parts = record_data.split()

                if len(parts) < 2:
                    continue

                priority = parts[0]
                host = parts[1].rstrip(".")

                # RFC 7505 Null MX:
                # priority 0 + target "." means mail is explicitly rejected.
                if priority == "0" and host == "":
                    return {
                        "status": "NULL_MX_EXPLICIT_REJECT",
                        "has_mx": False,
                        "retryable": False,
                        "mx_records": [],
                    }

                if host:
                    mx_hosts.append(host)

            if mx_hosts:
                return {
                    "status": "VALID_MAIL_EXCHANGE",
                    "has_mx": True,
                    "retryable": False,
                    "mx_records": mx_hosts,
                }

            return {
                "status": "NO_MX_RECORDS",
                "has_mx": False,
                "retryable": False,
                "mx_records": [],
            }

        # Other DNS response codes are not automatically treated as dead.
        return {
            "status": f"DNS_RCODE_{status_code}",
            "has_mx": None,
            "retryable": True,
            "mx_records": [],
        }

    def fetch_homepage_metadata(self) -> dict:
        """
        Fetch the first 64 KB of the HTTPS homepage.

        Extracts:
          - title
          - meta description
          - parked-domain signals
        """

        if not self.domain:
            return {
                "reachable": False,
                "title": "",
                "description": "",
                "is_parked": False,
            }

        url = f"https://{self.domain}"

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/120 Safari/537.36"
                )
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=4) as response:
                html = response.read()[:65536].decode(
                    "utf-8",
                    errors="ignore",
                )

        except (urllib.error.URLError, TimeoutError, socket.timeout):
            return {
                "reachable": False,
                "title": "",
                "description": "",
                "is_parked": False,
            }

        except UnicodeError:
            return {
                "reachable": False,
                "title": "",
                "description": "",
                "is_parked": False,
            }

        title_match = re.search(
            r"<title[^>]*>(.*?)</title>",
            html,
            re.IGNORECASE | re.DOTALL,
        )

        description_match = re.search(
            r'<meta\s+[^>]*name=["\']description["\'][^>]*'
            r'content=["\'](.*?)["\']',
            html,
            re.IGNORECASE | re.DOTALL,
        )

        if not description_match:
            description_match = re.search(
                r'<meta\s+[^>]*content=["\'](.*?)["\'][^>]*'
                r'name=["\']description["\']',
                html,
                re.IGNORECASE | re.DOTALL,
            )

        title = title_match.group(1).strip() if title_match else ""

        description = (
            description_match.group(1).strip()
            if description_match
            else ""
        )

        # Inspect title, description and first 64 KB of HTML.
        searchable_text = (
            title + " " + description + " " + html
        ).lower()

        parked_patterns = [
            r"domain\s+(is\s+)?for\s+sale",
            r"buy\s+this\s+domain",
            r"parked\s+free",
            r"godaddy.*domain",
            r"sedo",
            r"dan\.com",
            r"under\s+construction",
            r"renew\s+your\s+domain",
        ]

        is_parked = any(
            re.search(pattern, searchable_text)
            for pattern in parked_patterns
        )

        return {
            "reachable": True,
            "title": title,
            "description": description,
            "is_parked": is_parked,
        }

    def generate_email_candidates(self) -> list:
        """
        Generate deterministic email patterns.

        These are candidates only and MUST be verified
