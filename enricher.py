#!/usr/bin/env python3

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

VERSION = "1.3.0"


def sanitize_domain(value):
    if not isinstance(value, str):
        return ""

    value = value.strip().lower()

    if not value:
        return ""

    if value.startswith("//"):
        value = "https:" + value
    elif "://" not in value:
        value = "https://" + value

    try:
        host = urllib.parse.urlparse(value).hostname
    except ValueError:
        return ""

    if not host:
        return ""

    host = host.rstrip(".").lower()

    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass

    if host in ("localhost", "localhost.localdomain"):
        return ""

    if len(host) > 253:
        return ""

    if len(host.split(".")) < 2:
        return ""

    pattern = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    for label in host.split("."):
        if not label or len(label) > 63:
            return ""
        if not pattern.fullmatch(label):
            return ""

    return host


class ColdEngine:

    def __init__(
        self,
        raw_domain,
        first_name="",
        last_name="",
        company="",
    ):
        self.domain = sanitize_domain(raw_domain)
        self.first_name = self.clean_name(first_name)
        self.last_name = self.clean_name(last_name)
        self.company = company.strip()

        if not self.company and self.domain:
            self.company = self.domain.split(".")[0].capitalize()

    @staticmethod
    def clean_name(value):
        if not isinstance(value, str):
            return ""
        return re.sub(r"[^a-z0-9]", "", value.strip().lower())

    def check_mx_records(self):
        if not self.domain:
            return {
                "status": "INVALID_DOMAIN_FORMAT",
                "has_mx": False,
                "retryable": False,
                "mx_records": [],
            }

        url = (
            "https://dns.google/resolve?"
            + "name="
            + urllib.parse.quote(self.domain)
            + "&type=MX"
        )

        request = urllib.request.Request(
            url,
            headers={"User-Agent": "ColdEngine-OS/1.3.0"},
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=5,
            ) as response:
                data = json.loads(
                    response.read().decode("utf-8")
                )

        except (
            urllib.error.URLError,
            TimeoutError,
            socket.timeout,
        ) as exc:
            return {
                "status": (
                    "DNS_LOOKUP_ERROR: "
                    + type(exc).__name__
                ),
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

        status = data.get("Status")

        if not isinstance(status, int):
            return {
                "status": "DNS_INVALID_RESPONSE",
                "has_mx": None,
                "retryable": True,
                "mx_records": [],
            }

        if status == 3:
            return {
                "status": "NXDOMAIN",
                "has_mx": False,
                "retryable": False,
                "mx_records": [],
            }

        if status != 0:
            return {
                "status": f"DNS_RCODE_{status}",
                "has_mx": None,
                "retryable": True,
                "mx_records": [],
            }

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

        hosts = []

        for answer in answers:
            if not isinstance(answer, dict):
                continue

            record = answer.get("data", "")

            if not isinstance(record, str):
                continue

            parts = record.split()

            if len(parts) < 2:
                continue

            priority = parts[0]
            host = parts[1].rstrip(".")

            if priority == "0" and host == "":
                return {
                    "status": "NULL_MX_EXPLICIT_REJECT",
                    "has_mx": False,
                    "retryable": False,
                    "mx_records": [],
                }

            if host:
                hosts.append(host)

        if hosts:
            return {
                "status": "VALID_MAIL_EXCHANGE",
                "has_mx": True,
                "retryable": False,
                "mx_records": hosts,
            }

        return {
            "status": "NO_MX_RECORDS",
            "has_mx": False,
            "retryable": False,
            "mx_records": [],
        }

    def fetch_homepage_metadata(self):
        if not self.domain:
            return {
                "reachable": False,
                "status_code": None,
                "error": "INVALID_DOMAIN",
                "title": "",
                "description": "",
                "is_parked": False,
            }

        request = urllib.request.Request(
            "https://" + self.domain,
            headers={
                "User-Agent": "Mozilla/5.0 ColdEngine/1.3.0"
            },
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=4,
            ) as response:
                status_code = getattr(
                    response,
                    "status",
                    None,
                )

                html = response.read()[:65536].decode(
                    "utf-8",
                    errors="ignore",
                )

        except urllib.error.HTTPError as exc:
            return {
                "reachable": False,
                "status_code": exc.code,
                "error": f"HTTP_{exc.code}",
                "title": "",
                "description": "",
                "is_parked": False,
            }

        except (
            urllib.error.URLError,
            TimeoutError,
            socket.timeout,
        ) as exc:
            return {
                "reachable": False,
                "status_code": None,
                "error": type(exc).__name__,
                "title": "",
                "description": "",
                "is_parked": False,
            }

        title_match = re.search(
            r"<title[^>]*>(.*?)</title>",
            html,
            re.I | re.S,
        )

        desc_match = re.search(
            r'<meta\s+[^>]*name=["\']description["\']'
            r'[^>]*content=["\'](.*?)["\']',
            html,
            re.I | re.S,
        )

        if not desc_match:
            desc_match = re.search(
                r'<meta\s+[^>]*content=["\'](.*?)["\']'
                r'[^>]*name=["\']description["\']',
                html,
                re.I | re.S,
            )

        title = (
            title_match.group(1).strip()
            if title_match
            else ""
        )

        description = (
            desc_match.group(1).strip()
            if desc_match
            else ""
        )

        title_text = title.lower()
        description_text = description.lower()
        page_text = html.lower()

        strong_parked_patterns = [
            r"domain\s+(is\s+)?for\s+sale",
            r"buy\s+this\s+domain",
            r"this\s+domain\s+is\s+parked",
            r"parked\s+free",
            r"renew\s+your\s+domain",
        ]

        page_parked_patterns = [
            r"domain\s+for\s+sale",
            r"purchase\s+this\s+domain",
            r"domain\s+name\s+for\s+sale",
            r"under\s+construction",
            r"coming\s+soon",
            r"sedo",
            r"dan\.com",
            r"godaddy",
        ]

        strong_signal = any(
            re.search(pattern, title_text)
            or re.search(pattern, description_text)
            for pattern in strong_parked_patterns
        )

        page_signal_count = sum(
            1
            for pattern in page_parked_patterns
            if re.search(pattern, page_text)
        )

        parked = bool(
            strong_signal
            or page_signal_count >= 2
        )

        return {
            "reachable": True,
            "status_code": status_code,
            "error": "",
            "title": title,
            "description": description,
            "is_parked": parked,
        }

    def generate_email_candidates(self):
        if not self.first_name or not self.domain:
            return []

        fn = self.first_name
        ln = self.last_name
        domain = self.domain

        candidates = [
            f"{fn}@{domain}",
        ]

        if ln:
            candidates.extend(
                [
                    f"{fn}.{ln}@{domain}",
                    f"{fn[0]}{ln}@{domain}",
                    f"{fn}{ln[0]}@{domain}",
                    f"{ln}.{fn}@{domain}",
                ]
            )

        return candidates

    def run(self):
        mx = self.check_mx_records()

        if mx["has_mx"] is True:
            metadata = self.fetch_homepage_metadata()
        else:
            metadata = {
                "reachable": False,
                "status_code": None,
                "error": "",
                "title": "",
                "description": "",
                "is_parked": False,
            }

        dns_hard_reject = (
            mx["status"]
            in (
                "INVALID_DOMAIN_FORMAT",
                "NXDOMAIN",
                "NO_MX_RECORDS",
                "NULL_MX_EXPLICIT_REJECT",
            )
        )

        parked_hard_reject = bool(
            mx["has_mx"] is True
            and metadata["reachable"]
            and metadata["is_parked"]
        )

        hard_reject = bool(
            dns_hard_reject
            or parked_hard_reject
        )

        needs_review = bool(
            not hard_reject
            and mx["has_mx"] is True
            and not metadata["reachable"]
        )

        ready = bool(
            mx["has_mx"] is True
            and metadata["reachable"]
            and not metadata["is_parked"]
        )

        return {
            "version": VERSION,
            "domain": self.domain,
            "company": self.company,
            "dns_preflight": mx,
            "site_metadata": metadata,
            "email_candidates_unverified":
                self.generate_email_candidates(),
            "hard_reject": hard_reject,
            "needs_review": needs_review,
            "enrichment_ready": ready,
            "llm_prompt_payload": (
                f"Write a 1-sentence observational cold "
                f"outreach opener for {self.company}. "
                f"Context: {metadata['title']} - "
                f"{metadata['description']}"
            ) if ready else None,
        }


def process_bulk_csv(input_path, output_path):
    with open(
        input_path,
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as infile:
        reader = csv.DictReader(infile)
        rows = list(reader)

    if not rows:
        raise ValueError(
            f"No data found in {input_path}"
        )

    fields = list(rows[0].keys())

    domain_col = next(
        (
            x for x in fields
            if x.lower() in (
                "domain",
                "website",
                "company_domain",
            )
        ),
        fields[0],
    )

    first_col = next(
        (
            x for x in fields
            if x.lower() in (
                "first_name",
                "first",
                "firstname",
            )
        ),
        None,
    )

    last_col = next(
        (
            x for x in fields
            if x.lower() in (
                "last_name",
                "last",
                "lastname",
            )
        ),
        None,
    )

    company_col = next(
        (
            x for x in fields
            if x.lower() in (
                "company",
                "company_name",
            )
        ),
        None,
    )

    extra = [
        "coldengine_status",
        "coldengine_has_mx",
        "coldengine_retryable",
        "coldengine_is_parked",
        "coldengine_site_reachable",
        "coldengine_site_error",
        "coldengine_hard_reject",
        "coldengine_needs_review",
        "coldengine_ready",
        "coldengine_candidates",
    ]

    output_fields = fields + [
        x for x in extra if x not in fields
    ]

    output_rows = []

    for row in rows:
        try:
            engine = ColdEngine(
                row.get(domain_col, ""),
                row.get(first_col, "") if first_col else "",
                row.get(last_col, "") if last_col else "",
                row.get(company_col, "") if company_col else "",
            )

            result = engine.run()

            out = dict(row)

            out["coldengine_status"] = (
                result["dns_preflight"]["status"]
            )

            out["coldengine_has_mx"] = str(
                result["dns_preflight"]["has_mx"]
            )

            out["coldengine_retryable"] = str(
                result["dns_preflight"]["retryable"]
            )

            out["coldengine_is_parked"] = str(
                result["site_metadata"]["is_parked"]
            )

            out["coldengine_site_reachable"] = str(
                result["site_metadata"]["reachable"]
            )

            out["coldengine_site_error"] = (
                result["site_metadata"]["error"]
            )

            out["coldengine_hard_reject"] = str(
                result["hard_reject"]
            )

            out["coldengine_needs_review"] = str(
                result["needs_review"]
            )

            out["coldengine_ready"] = str(
                result["enrichment_ready"]
            )

            out["coldengine_candidates"] = ";".join(
                result["email_candidates_unverified"]
            )

            output_rows.append(out)

        except Exception as exc:
            out = dict(row)

            out["coldengine_status"] = (
                "ROW_PROCESSING_ERROR: "
                + type(exc).__name__
            )

            out["coldengine_has_mx"] = ""
            out["coldengine_retryable"] = "False"
            out["coldengine_is_parked"] = "False"
            out["coldengine_site_reachable"] = "False"
            out["coldengine_site_error"] = (
                type(exc).__name__
            )
            out["coldengine_hard_reject"] = "False"
            out["coldengine_needs_review"] = "True"
            out["coldengine_ready"] = "False"
            out["coldengine_candidates"] = ""

            output_rows.append(out)

    with open(
        output_path,
        "w",
        encoding="utf-8",
        newline="",
    ) as outfile:
        writer = csv.DictWriter(
            outfile,
            fieldnames=output_fields,
        )
        writer.writeheader()
        writer.writerows(output_rows)

    print(
        f"Done. Wrote {len(output_rows)} rows "
        f"to {output_path}"
    )


def main():
    parser = argparse.ArgumentParser(
        description="ColdEngine OS B2B Lead Pre-Filter"
    )

    parser.add_argument(
        "domain",
        nargs="?",
        default=None,
    )

    parser.add_argument(
        "--first",
        default="",
    )

    parser.add_argument(
        "--last",
        default="",
    )

    parser.add_argument(
        "--company",
        default="",
    )

    parser.add_argument(
        "--csv",
        default=None,
    )

    parser.add_argument(
        "--out",
        default="enriched_leads.csv",
    )

    args = parser.parse_args()

    if args.csv:
        try:
            process_bulk_csv(
                args.csv,
                args.out,
            )
        except (
            OSError,
            ValueError,
        ) as exc:
            print(
                f"Error: {exc}",
                file=sys.stderr,
            )
            sys.exit(1)

    elif args.domain:
        engine = ColdEngine(
            args.domain,
            args.first,
            args.last,
            args.company,
        )

        print(
            json.dumps(
                engine.run(),
                indent=2,
            )
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
           
