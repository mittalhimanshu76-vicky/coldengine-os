import csv
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from enricher import ColdEngine, process_bulk_csv, sanitize_domain


class FakeResponse:
    """Minimal context-manager response for mocked urllib calls."""

    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class TestDomainSanitization(unittest.TestCase):

    def test_https_url(self):
        self.assertEqual(
            sanitize_domain("https://vercel.com/pricing"),
            "vercel.com",
        )

    def test_http_url(self):
        self.assertEqual(
            sanitize_domain("http://sub.domain.co.uk/"),
            "sub.domain.co.uk",
        )

    def test_bare_domain(self):
        self.assertEqual(
            sanitize_domain("  STRIPE.COM  "),
            "stripe.com",
        )

    def test_port(self):
        self.assertEqual(
            sanitize_domain("https://example.com:443/path"),
            "example.com",
        )

    def test_protocol_relative_url(self):
        self.assertEqual(
            sanitize_domain("//example.com/path"),
            "example.com",
        )

    def test_credentials_are_not_part_of_domain(self):
        self.assertEqual(
            sanitize_domain(
                "https://user:password@example.com/path"
            ),
            "example.com",
        )

    def test_trailing_dot(self):
        self.assertEqual(
            sanitize_domain("example.com."),
            "example.com",
        )

    def test_invalid_domain(self):
        self.assertEqual(
            sanitize_domain("not a domain"),
            "",
        )

    def test_localhost_rejected(self):
        self.assertEqual(
            sanitize_domain("localhost"),
            "",
        )

    def test_ip_rejected(self):
        self.assertEqual(
            sanitize_domain("https://127.0.0.1"),
            "",
        )

    def test_empty_input(self):
        self.assertEqual(
            sanitize_domain(""),
            "",
        )


class TestDNS(unittest.TestCase):

    def mock_dns(self, payload):
        response = FakeResponse(
            json.dumps(payload).encode("utf-8")
        )
        return patch(
            "enricher.urllib.request.urlopen",
            return_value=response,
        )

    def test_valid_mx(self):
        payload = {
            "Status": 0,
            "Answer": [
                {
                    "data": "10 aspmx.l.google.com."
                }
            ],
        }

        with self.mock_dns(payload):
            result = ColdEngine("google.com").check_mx_records()

        self.assertEqual(
            result["status"],
            "VALID_MAIL_EXCHANGE",
        )
        self.assertTrue(result["has_mx"])
        self.assertFalse(result["retryable"])
        self.assertEqual(
            result["mx_records"],
            ["aspmx.l.google.com"],
        )

    def test_null_mx(self):
        payload = {
            "Status": 0,
            "Answer": [
                {
                    "data": "0 ."
                }
            ],
        }

        with self.mock_dns(payload):
            result = ColdEngine("example.com").check_mx_records()

        self.assertEqual(
            result["status"],
            "NULL_MX_EXPLICIT_REJECT",
        )
        self.assertFalse(result["has_mx"])
        self.assertFalse(result["retryable"])
        self.assertEqual(
            result["mx_records"],
            [],
        )

    def test_nxdomain(self):
        payload = {
            "Status": 3
        }

        with self.mock_dns(payload):
            result = ColdEngine(
                "does-not-exist.example"
            ).check_mx_records()

        self.assertEqual(
            result["status"],
            "NXDOMAIN",
        )
        self.assertFalse(result["has_mx"])
        self.assertFalse(result["retryable"])

    def test_no_mx_records(self):
        payload = {
            "Status": 0,
            "Answer": [],
        }

        with self.mock_dns(payload):
            result = ColdEngine(
                "example.com"
            ).check_mx_records()

        self.assertEqual(
            result["status"],
            "NO_MX_RECORDS",
        )
        self.assertFalse(result["has_mx"])
        self.assertFalse(result["retryable"])

    def test_dns_timeout_is_retryable(self):
        with patch(
            "enricher.urllib.request.urlopen",
            side_effect=TimeoutError(),
        ):
            result = ColdEngine(
                "example.com"
            ).check_mx_records()

        self.assertTrue(result["retryable"])
        self.assertIsNone(result["has_mx"])
        self.assertIn(
            "DNS_LOOKUP_ERROR",
            result["status"],
        )

    def test_dns_url_error_is_retryable(self):
        import urllib.error

        with patch(
            "enricher.urllib.request.urlopen",
            side_effect=urllib.error.URLError(
                "temporary failure"
            ),
        ):
            result = ColdEngine(
                "example.com"
            ).check_mx_records()

        self.assertTrue(result["retryable"])
        self.assertIsNone(result["has_mx"])

    def test_invalid_json_is_retryable(self):
        response = FakeResponse(
            b"this is not json"
        )

        with patch(
            "enricher.urllib.request.urlopen",
            return_value=response,
        ):
            result = ColdEngine(
                "example.com"
            ).check_mx_records()

        self.assertEqual(
            result["status"],
            "DNS_INVALID_JSON",
        )
        self.assertTrue(result["retryable"])
        self.assertIsNone(result["has_mx"])

    def test_invalid_dns_response(self):
        payload = {
            "unexpected": "response"
        }

        with self.mock_dns(payload):
            result = ColdEngine(
                "example.com"
            ).check_mx_records()

        self.assertEqual(
            result["status"],
            "DNS_INVALID_RESPONSE",
        )
        self.assertTrue(result["retryable"])


class TestHomepageMetadata(unittest.TestCase):

    def mock_homepage(self, html):
        response = FakeResponse(
            html.encode("utf-8")
        )

        return patch(
            "enricher.urllib.request.urlopen",
            return_value=response,
        )

    def test_metadata_extraction(self):
        html = """
        <html>
        <head>
            <title>Acme Logistics</title>
            <meta name="description"
                  content="Industrial logistics company">
        </head>
        <body>
            <p>Hello</p>
        </body>
        </html>
        """

        with self.mock_homepage(html):
            result = ColdEngine(
                "acme.com"
            ).fetch_homepage_metadata()

        self.assertTrue(result["reachable"])
        self.assertEqual(
            result["title"],
            "Acme Logistics",
        )
        self.assertEqual(
            result["description"],
            "Industrial logistics company",
        )
        self.assertFalse(result["is_parked"])

    def test_description_attribute_order(self):
        html = """
        <html>
        <head>
            <title>Acme</title>
            <meta content="Industrial company"
                  name="description">
        </head>
        </html>
        """

        with self.mock_homepage(html):
            result = ColdEngine(
                "acme.com"
            ).fetch_homepage_metadata()

        self.assertEqual(
            result["description"],
            "Industrial company",
        )

    def test_parked_domain(self):
        html = """
        <html>
        <head>
            <title>This Domain Is For Sale</title>
            <meta name="description"
                  content="Buy this domain">
        </head>
        </html>
        """

        with self.mock_homepage(html):
            result = ColdEngine(
                "parked-example.com"
            ).fetch_homepage_metadata()

        self.assertTrue(result["reachable"])
        self.assertTrue(result["is_parked"])

    def test_parked_domain_in_body(self):
        html = """
        <html>
        <head>
            <title>Example</title>
        </head>
        <body>
            This domain is for sale.
        </body>
        </html>
        """

        with self.mock_homepage(html):
            result = ColdEngine(
                "parked-example.com"
            ).fetch_homepage_metadata()

        self.assertTrue(result["is_parked"])

    def test_homepage_failure(self):
        import urllib.error

        with patch(
            "enricher.urllib.request.urlopen",
            side_effect=urllib.error.URLError(
                "connection failed"
            ),
        ):
            result = ColdEngine(
                "example.com"
            ).fetch_homepage_metadata()

        self.assertFalse(result["reachable"])
        self.assertEqual(
            result["title"],
            "",
        )
        self.assertEqual(
            result["description"],
            "",
        )
        self.assertFalse(result["is_parked"])


class TestEmailCandidates(unittest.TestCase):

    def test_candidate_generation(self):
        engine = ColdEngine(
            "linear.app",
            first_name="Karri",
            last_name="Saarinen",
        )

        candidates = (
            engine.generate_email_candidates()
        )

        self.assertIn(
            "karri@linear.app",
            candidates,
        )

        self.assertIn(
            "karri.saarinen@linear.app",
            candidates,
        )

        self.assertIn(
            "ksaarinen@linear.app",
            candidates,
        )

        self.assertIn(
            "karris@linear.app",
            candidates,
        )

        self.assertIn(
            "saarinen.karri@linear.app",
            candidates,
        )

    def test_name_normalization(self):
        engine = ColdEngine(
            "example.com",
            first_name="Mary Jane",
            last_name="O'Neil",
        )

        candidates = (
            engine.generate_email_candidates()
        )

        self.assertIn(
            "maryjane@example.com",
            candidates,
        )

        self.assertIn(
            "maryjane.oneil@example.com",
            candidates,
        )

    def test_missing_first_name(self):
        engine = ColdEngine(
            "example.com",
            last_name="Smith",
        )

        self.assertEqual(
            engine.generate_email_candidates(),
            [],
        )


class TestRun(unittest.TestCase):

    def test_run_ready_domain(self):
        dns_payload = {
            "Status": 0,
            "Answer": [
                {
                    "data": "10 mail.example.com."
                }
            ],
        }

        homepage_html = """
        <html>
        <head>
            <title>Example Company</title>
            <meta name="description"
                  content="A B2B company">
        </head>
        </html>
        """

        dns_response = FakeResponse(
            json.dumps(dns_payload).encode("utf-8")
        )

        homepage_response = FakeResponse(
            homepage_html.encode("utf-8")
        )

        with patch(
            "enricher.urllib.request.urlopen",
            side_effect=[
                dns_response,
                homepage_response,
            ],
        ):
            result = ColdEngine(
                "example.com",
                first_name="John",
                last_name="Smith",
                company="Example Company",
            ).run()

        self.assertTrue(
            result["enrichment_ready"]
        )

        self.assertIsNotNone(
            result["llm_prompt_payload"]
        )

        self.assertEqual(
            result["version"],
            "1.3.0",
        )

    def test_run_does_not_fetch_homepage_without_mx(self):
        dns_payload = {
            "Status": 3
        }

        dns_response = FakeResponse(
            json.dumps(dns_payload).encode("utf-8")
        )

        with patch(
            "enricher.urllib.request.urlopen",
            return_value=dns_response,
        ) as mocked_urlopen:

            result = ColdEngine(
                "example.com"
            ).run()

        self.assertFalse(
            result["enrichment_ready"]
        )

        self.assertIsNone(
            result["llm_prompt_payload"]
        )

        # Only DNS should have been called.
        self.assertEqual(
            mocked_urlopen.call_count,
            1,
        )


class TestBulkCSV(unittest.TestCase):

    def test_bulk_csv_processes_all_rows(self):
        dns_payload = {
            "Status": 0,
            "Answer": [
                {
                    "data": "10 mail.example.com."
                }
            ],
        }

        dns_response = FakeResponse(
            json.dumps(dns_payload).encode("utf-8")
        )

        with tempfile.TemporaryDirectory() as tmpdir:

            input_path = os.path.join(
                tmpdir,
                "input.csv",
            )

            output_path = os.path.join(
                tmpdir,
                "output.csv",
            )

            rows = []

            for index in range(100):
                rows.append(
                    {
                        "domain": f"company{index}.com",
                        "first_name": "John",
                        "last_name": "Smith",
                        "company": f"Company {index}",
                    }
                )

            with open(
                input_path,
                "w",
                encoding="utf-8",
                newline="",
            ) as infile:

                writer = csv.DictWriter(
                    infile,
                    fieldnames=[
                        "domain",
                        "first_name",
                        "last_name",
                        "company",
                    ],
                )

                writer.writeheader()
                writer.writerows(rows)

            homepage_html = """
            <html>
            <head>
                <title>Example Company</title>
                <meta name="description"
                      content="Example business">
            </head>
            </html>
            """

            homepage_response = FakeResponse(
                homepage_html.encode("utf-8")
            )

            # Each row requires one DNS call + one homepage call.
            responses = []

            for _ in range(100):
                responses.append(
                    FakeResponse(
                        json.dumps(
                            dns_payload
                        ).encode("utf-8")
                    )
                )

                responses.append(
                    FakeResponse(
                        homepage_html.encode("utf-8")
                    )
                )

            with patch(
                "enricher.urllib.request.urlopen",
                side_effect=responses,
            ):
                process_bulk_csv(
                    input_path,
                    output_path,
                )

            with open(
                output_path,
                "r",
                encoding="utf-8",
                newline="",
            ) as outfile:

                output_rows = list(
                    csv.DictReader(outfile)
                )

            self.assertEqual(
                len(output_rows),
                100,
            )

            for row in output_rows:
                self.assertEqual(
                    row["coldengine_status"],
                    "VALID_MAIL_EXCHANGE",
                )

                self.assertEqual(
                    row["coldengine_has_mx"],
                    "True",
                )

                self.assertEqual(
                    row["coldengine_retryable"],
                    "False",
                )

                self.assertEqual(
                    row["coldengine_ready"],
                    "True",
                )

                self.assertTrue(
                    row["coldengine_candidates"]
                )


if __name__ == "__main__":
    unittest.main()
