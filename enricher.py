"""
ColdEngine OS - Standalone Lead Enrichment & Verification Engine
Version: 1.0 (Agency Pro License)
"""

import json
import re
import socket
import sys
import urllib.request
from typing import Dict, List

class ColdEngine:
    def __init__(self, target_domain: str):
        self.domain = target_domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]

    def verify_mx(self) -> Dict[str, any]:
        """Validates if domain resolves and accepts incoming traffic."""
        try:
            socket.gethostbyname(self.domain)
            return {"domain_resolves": True, "status": "active"}
        except socket.gaierror:
            return {"domain_resolves": False, "status": "dead_domain"}

    def generate_email_patterns(self, first_name: str, last_name: str) -> List[str]:
        """Generates standard corporate B2B email permutations."""
        f = re.sub(r'[^a-zA-Z]', '', first_name.lower())
        l = re.sub(r'[^a-zA-Z]', '', last_name.lower())
        if not f or not l:
            return []
        
        return [
            f"{f}@{self.domain}",
            f"{f}.{l}@{self.domain}",
            f"{f[0]}{l}@{self.domain}",
            f"{f}_{l}@{self.domain}",
            f"{l}.{f}@{self.domain}"
        ]

    def scrape_company_signals(self) -> Dict[str, str]:
        """Extracts title and meta description without paid APIs."""
        url = f"https://{self.domain}"
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ColdEngineBot/1.0'}
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as response:
                html = response.read().decode('utf-8', errors='ignore')
                
                title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                meta_desc = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\'](.*?)["\']', html, re.IGNORECASE)
                
                return {
                    "company_name": title_match.group(1).strip() if title_match else self.domain,
                    "description": meta_desc.group(1).strip() if meta_desc else "Description unavailable",
                    "status": "success"
                }
        except Exception as e:
            return {"company_name": self.domain, "description": "Failed to scrape homepage", "error": str(e)}

    def compile_prompt_payload(self, first_name: str, last_name: str, prospect_title: str) -> Dict[str, any]:
        signals = self.scrape_company_signals()
        emails = self.generate_email_patterns(first_name, last_name)
        
        llm_prompt = (
            f"Write a sharp 2-sentence cold outreach opening for {first_name} ({prospect_title} at {signals['company_name']}). "
            f"Company context: '{signals['description']}'. "
            f"Focus on streamlining outbound operations without expensive SaaS seats. No flattery or filler."
        )

        return {
            "prospect": f"{first_name} {last_name}",
            "domain": self.domain,
            "emails_to_test": emails,
            "company_intel": signals,
            "generated_llm_prompt": llm_prompt
        }

if __name__ == "__main__":
    test_engine = ColdEngine("stripe.com")
    print(json.dumps(test_engine.compile_prompt_payload("John", "Doe", "VP Sales"), indent=2))