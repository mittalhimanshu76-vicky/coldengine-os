#!/usr/bin/env python3
"""
ColdEngine OS (v1.2) - B2B Lead Intelligence Pre-Flight Engine
Pure Python standard library. Zero external dependencies.
"""

import argparse
import csv
import json
import re
import sys
import urllib.parse
import urllib.request


def sanitize_domain(raw_input: str) -> str:
    """Extracts clean FQDN from messy user inputs, raw URLs, or paths."""
    raw = raw_input.strip().lower()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urllib.parse.urlparse(raw)
    domain = parsed.netloc or parsed.path
    return domain.split(":")[0].strip("/")


class ColdEngine:
    def __init__(self, raw_domain: str, first_name: str = "", last_name: str = "", company: str = ""):
        self.domain = sanitize_domain(raw_domain)
        self.first_name = first_name.strip().lower()
        self.last_name = last_name.strip().lower()
        self.company = company.strip() or (self.domain.split(".")[0].capitalize() if self.domain else "")

    def check_mx_records(self) -> dict:
        """
        Queries Google DoH over port 443 with RFC 7505 Null MX detection
        and explicit error/NXDOMAIN separation.
        """
        if not self.domain or "." not in self.domain:
            return {"status": "INVALID_DOMAIN_FORMAT", "has_mx": False, "retryable": False, "mx_records": []}

        doh_url = f"https://dns.google/resolve?name={urllib.parse.quote(self.domain)}&type=MX"
        req = urllib.request.Request(
            doh_url,
            headers={"User-Agent": "ColdEngine-OS/1.2 (Pre-Flight Engine)"}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))

            status_code = data.get("Status", -1)

            # RCODE 3 = NXDOMAIN (Domain does not exist)
            if status_code == 3:
                return {"status": "NXDOMAIN", "has_mx": False, "retryable": False, "mx_records": []}

            # RCODE 0 = NOERROR
            if status_code == 0:
                answers = data.get("Answer", [])
                if not answers:
                    return {"status": "NO_MX_RECORDS", "has_mx": False, "retryable": False, "mx_records": []}

                mx_hosts = []
                for ans in answers:
                    parts = ans.get("data", "").split()
                    if len(parts) >= 2:
                        host = parts[1].rstrip(".")
                        # RFC 7505: Explicit Null MX (priority 0, target ".")
                        if parts[0] == "0" and host in ("", "."):
                            return {"status": "NULL_MX_EXPLICIT_REJECT", "has_mx": False, "retryable": False, "mx_records": []}
                        if host and host != ".":
                            mx_hosts.append(host)

                if mx_hosts:
                    return {"status": "VALID_MAIL_EXCHANGE", "has_mx": True, "retryable": False, "mx_records": mx_hosts}

            return {"status": f"DNS_RCODE_{status_code}", "has_mx": False, "retryable": False, "mx_records": []}

        except Exception as e:
            # Network drops/timeouts should be flagged for retry, not marked dead
            return {"status": f"DNS_LOOKUP_ERROR: {type(e).__name__}", "has_mx": None, "retryable": True, "mx_records": []}

    def fetch_homepage_metadata(self) -> dict:
        """Lightweight HTTP metadata fetch with timeout guarding and parked domain heuristics."""
        if not self.domain:
            return {"reachable": False, "title": "", "description": "", "is_parked": False}

        url = f"https://{self.domain}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"}
        )
        try:
            with urllib.request.urlopen(req, timeout=4) as response:
                html = response.read()[:65536].decode("utf-8", errors="ignore")  # Read first 64KB only

            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            desc_match = re.search(
                r'<meta\s+[^>]*name=["\']description["\'][^>]*content=["\'](.*?)["\']',
                html, re.IGNORECASE | re.DOTALL
            ) or re.search(
                r'<meta\s+[^>]*content=["\'](.*?)["\'][^>]*name=["\']description["\']',
                html, re.IGNORECASE | re.DOTALL
            )

            title = title_match.group(1).strip() if title_match else ""
            description = desc_match.group(1).strip() if desc_match else ""

            # Check parked signatures across title, description, and raw body
            body_sample = (title + " " + description).lower()
            parked_patterns = [
                r"domain (is )?for sale",
                r"buy this domain",
                r"parked free",
                r"godaddy.*domain",
                r"dan\.com",
                r"under construction",
                r"renew your domain"
            ]
            is_parked = any(re.search(pat, body_sample) for pat in parked_patterns)

            return {
                "reachable": True,
                "title": title,
                "description": description,
                "is_parked": is_parked
            }
        except Exception:
            return {"reachable": False, "title": "", "description": "", "is_parked": False}

    def generate_email_candidates(self) -> list:
        """Deterministic address candidates (requires downstream mailbox verification)."""
        if not self.first_name or not self.domain:
            return []
        fn, ln, d = self.first_name, self.last_name, self.domain
        candidates = [f"{fn}@{d}"]
        if ln:
            candidates.extend([
                f"{fn}.{ln}@{d}",
                f"{fn[0]}{ln}@{d}",
                f"{fn}{ln[0]}@{d}",
                f"{ln}.{fn}@{d}"
            ])
        return candidates

    def run(self) -> dict:
        mx = self.check_mx_records()
        metadata = self.fetch_homepage_metadata() if mx["has_mx"] else {"reachable": False, "title": "", "description": "", "is_parked": False}
        candidates = self.generate_email_candidates()

        enrichment_ready = bool(mx["has_mx"] and metadata["reachable"] and not metadata["is_parked"])

        return {
            "domain": self.domain,
            "company": self.company,
            "dns_preflight": mx,
            "site_metadata": metadata,
            "email_candidates_unverified": candidates,
            "enrichment_ready": enrichment_ready,
            "llm_prompt_payload": (
                f"Write a 1-sentence observational cold outreach opener for {self.company}. "
                f"Context: {metadata['title']} - {metadata['description']}"
            ) if enrichment_ready else None
        }


def process_bulk_csv(input_path: str, output_path: str):
    """Processes CSV files in bulk and writes structured results."""
    with open(input_path, mode="r", encoding="utf-8-sig") as infile:
        reader = csv.DictReader(infile)
        rows = list(reader)

    if not rows:
        print(f"Error: No data found in {input_path}")
        return

    # Normalize column lookups
    fieldnames = list(rows[0].keys())
    domain_col = next((col for col in fieldnames if col.lower() in ("domain", "website", "company_domain")), fieldnames[0])
    first_col = next((col for col in fieldnames if col.lower() in ("first_name", "first", "firstname")), None)
    last_col = next((col for col in fieldnames if col.lower() in ("last_name", "last", "lastname")), None)
    comp_col = next((col for col in fieldnames if col.lower() in ("company", "company_name")), None)

    out_fieldnames = fieldnames + [
        "coldengine_status", "coldengine_has_mx", "coldengine_retryable",
        "coldengine_is_parked", "coldengine_ready", "coldengine_candidates"
    ]

    processed = []
    print(f"Processing {len(rows)} records from {input_path}...")

    for row in rows:
        engine = ColdEngine(
            raw_domain=row.get(domain_col, ""),
            first_name=row.get(first_col, "") if first_col else "",
            last_name=row.get(last_col, "") if last_col else "",
            company=row.get(comp_col, "") if comp_col else ""
        )
        res = engine.run()
        out_row = dict(row)
        out_row["coldengine_status"] = res["dns_preflight"]["status"]
        out_row["coldengine_has_mx"] = str(res["dns_preflight"]["has_mx"])
        out_row["coldengine_retryable"] = str(res["dns_preflight"]["retryable"])
        out_row["coldengine_is_parked"] = str(res["site_metadata"]["is_parked"])
        out_row["coldengine_ready"] = str(res["enrichment_ready"])
        out_row["coldengine_candidates"] = ";".join(res["email_candidates_unverified"])
        processed.append(out_row)

    with open(output_path, mode="w", encoding="utf-8", newline="") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=out_fieldnames)
        writer.writeheader()
        writer.writerows(processed)

    print(f"Done. Wrote {len(processed)} enriched rows to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="ColdEngine OS - B2B Lead Intelligence Pre-Flight Engine")
    parser.add_argument("domain", nargs="?", default=None, help="Target root domain or URL (e.g. https://vercel.com)")
    parser.add_argument("--first", default="", help="Lead first name")
    parser.add_argument("--last", default="", help="Lead last name")
    parser.add_argument("--company", default="", help="Lead company name")
    parser.add_argument("--csv", default=None, help="Path to input CSV for bulk batch processing")
    parser.add_argument("--out", default="enriched_leads.csv", help="Path to output CSV (used with --csv)")

    args = parser.parse_args()

    if args.csv:
        process_bulk_csv(args.csv, args.out)
    elif args.domain:
        engine = ColdEngine(raw_domain=args.domain, first_name=args.first, last_name=args.last, company=args.company)
        print(json.dumps(engine.run(), indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
    
