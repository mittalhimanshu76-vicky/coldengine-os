# ColdEngine OS

Lightweight, open-source B2B lead pre-flight verification and metadata enrichment engine for outbound teams. 

Run pre-enrichment checks locally using pure Python (zero external dependencies) or import the visual waterfall into self-hosted n8n to eliminate paid credit waste on dead or parked domains.

---

## The Problem: Credit Burn on Dead Leads

Running raw, uncleaned lead lists directly through credit-based enrichment tools burns paid credits on domains that do not even have active mail servers. Between 15% and 30% of scraped domains are dead, expired, or parked.

ColdEngine OS acts as a **zero-cost pre-flight filter** before leads hit downstream catch-all verifiers, search APIs, or sending platforms.

---

## What ColdEngine OS Does

1. **DNS-over-HTTPS (DoH) MX Validation (Port 443):** Queries Google's public DoH resolver to confirm active Mail Exchangers. It never initiates port 25 handshakes, avoiding IP blacklists and ISP blocks.
2. **Sub-300ms Root Metadata Extraction:** Uses the pure Python standard library to parse `<title>` and `<meta name="description">` tags without running headless browser binaries.
3. **Parked Domain Filtering:** Flags domain parking pages (GoDaddy, Sedo, Dan) before spending downstream resources.
4. **Email Permutation Generation:** Generates deterministic address patterns (`first@`, `first.last@`, `flast@`) ready for downstream catch-all checking.
5. **Structured LLM Prompt Payload:** Compiles clean company metadata into a minimal payload ready for `gpt-4o-mini`, cutting token consumption to ~$2 per 1,000 leads.

---

## Quickstart (CLI)

No `pip install` required. Built entirely on the Python 3 standard library.

```bash
# Clone the repository
git clone [https://github.com/mittalhimanshu76-vicky/coldengine-os.git](https://github.com/mittalhimanshu76-vicky/coldengine-os.git)
cd coldengine-os

# Run pre-flight check on a domain
python3 enricher.py vercel.com --first Guillermo --last Rauch --company Vercel
