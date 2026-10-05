#!/usr/bin/env python3
"""
ColdEngine OS (v1.1) - Lightweight B2B Lead Intelligence & Pre-Flight Engine
Pure Python standard library. Zero external dependencies.
"""

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request


class ColdEngine:
    def __init__(self, domain: str, first_name: str = "", last_name: str = "", company: str = ""):
        self.domain = domain.strip().lower()
        self.first_name = first_name.strip().lower()
        self.last_name = last_name.strip().lower()
        self.company = company.strip() or self.domain.split(".")[0].capitalize()

    def check_mx_records(self) -> dict:
        """
        Performs genuine MX record lookup using Google DNS-over-HTTPS (DoH).
        Runs over port 443 without touching port 25 or triggering ISP blocking.
        """
        doh_url = f"https://dns.google/resolve?name={urllib.parse.quote(self.domain)}&type=MX"
        req = urllib.request.Request(
            doh_url,
            headers={"User-Agent": "ColdEngine-OS/1.1 (DNS Pre-Flight Check)"}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))

            status = data.get("Status", -1)
            answers = data.get("Answer", [])

            if status == 0 and answers:
                mx_hosts = [ans.get("data", "").split()[-1].rstrip(".") for ans in answers if "data" in ans]
                return {
                    "has_mx": True,
                    "status": "VALID_MAIL_EXCHANGE",
                    "mx_records": mx_hosts
                }
            return {
                "has_mx": False,
                "status": "NO_MX_RECORDS",
                "mx_records": []
            }
        except Exception as e:
            return {
                "has_mx": False,
                "status": f"DNS_QUERY_FAILED: {str(e)}",
                "mx_records": []
            }

    def fetch_homepage_metadata(self) -> dict:
        """
        Lightweight HTTP metadata scraper (sub-300ms, non-headless).
        Extracts title, meta description, and parking indicators.
        """
        url = f"https://{self.domain}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        try:
            with urllib.request.urlopen(req, timeout=4) as response:
                html = response.read().decode("utf-8", errors="ignore")

            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            desc_match = re.search(
                r'<meta\s+[^>]*name=["\']description["\'][^>]*content=["\'](.*?)["\']',
                html,
                re.IGNORECASE | re.DOTALL
            ) or re.search(
                r'<meta\s+[^>]*content=["\'](.*?)["\'][^>]*name=["\']description["\']',
                html,
                re.IGNORECASE | re.DOTALL
            )

            title = title_match.group(1).strip() if title_match else ""
            description = desc_match.group(1).strip() if desc_match else ""

            # Detect parked/for-sale domain footprints
            parking_signals = ["domain for sale", "buy this domain", "parked free", "godaddy", "dan.com", "namecheap"]
            is_parked = any(sig in (title + " " + description).lower() for sig in parking_signals)

            return {
                "reachable": True,
                "title": title,
                "description": description,
                "is_parked": is_parked
            }
        except Exception:
            return {
                "reachable": False,
                "title": "",
                "description": "",
                "is_parked": False
            }

    def generate_email_permutations(self) -> list:
        """Generates standard candidate address patterns (unverified)."""
        if not self.first_name:
            return []
        
        d = self.domain
        fn = self.first_name
        ln = self.last_name
        
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
        mx_result = self.check_mx_records()
        metadata = self.fetch_homepage_metadata() if mx_result["has_mx"] else {"reachable": False, "title": "", "description": "", "is_parked": False}
        candidates = self.generate_email_permutations()

        # Build clean LLM prompt payload ready to feed into any inference engine
        llm_context = {
            "company": self.company,
            "title": metadata["title"],
            "description": metadata["description"]
        } if metadata["reachable"] and not metadata["is_parked"] else None

        return {
            "domain": self.domain,
            "company": self.company,
            "dns_preflight": mx_result,
            "site_metadata": metadata,
            "email_candidates_unverified": candidates,
            "enrichment_ready": bool(llm_context),
            "llm_prompt_payload": (
                f"Write a 1-sentence observational cold outreach opener for {self.company}. "
                f"Context: {metadata['title']} - {metadata['description']}"
            ) if llm_context else None
        }


def main():
    parser = argparse.ArgumentParser(description="ColdEngine OS - Open-Source Lead Intelligence Pre-Filter")
    parser.add_argument("domain", help="Target company root domain (e.g. vercel.com)")
    parser.add_argument("--first", default="", help="Lead first name")
    parser.add_argument("--last", default="", help="Lead last name")
    parser.add_argument("--company", default="", help="Lead company name (optional)")

    args = parser.parse_args()
    engine = ColdEngine(domain=args.domain, first_name=args.first, last_name=args.last, company=args.company)
    print(json.dumps(engine.run(), indent=2))


if __name__ == "__main__":
    main()
    
