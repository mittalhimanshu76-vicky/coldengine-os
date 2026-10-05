import unittest
from enricher import ColdEngine, sanitize_domain


class TestColdEngine(unittest.TestCase):

    def test_domain_sanitization(self):
        self.assertEqual(
            sanitize_domain("https://vercel.com/pricing"),
            "vercel.com"
        )
        self.assertEqual(
            sanitize_domain("http://sub.domain.co.uk/"),
            "sub.domain.co.uk"
        )
        self.assertEqual(
            sanitize_domain("  stripe.com  "),
            "stripe.com"
        )
        self.assertEqual(
            sanitize_domain("https://example.com:443/path"),
            "example.com"
        )

    def test_active_mx(self):
        engine = ColdEngine("google.com")
        res = engine.check_mx_records()

        self.assertTrue(res["has_mx"])
        self.assertEqual(
            res["status"],
            "VALID_MAIL_EXCHANGE"
        )
        self.assertFalse(res["retryable"])

    def test_nxdomain(self):
        engine = ColdEngine(
            "this-domain-does-not-exist-coldengine-test-123.com"
        )
        res = engine.check_mx_records()

        self.assertFalse(res["has_mx"])
        self.assertEqual(res["status"], "NXDOMAIN")
        self.assertFalse(res["retryable"])

    def test_candidate_generation(self):
        engine = ColdEngine(
            "linear.app",
            first_name="Karri",
            last_name="Saarinen"
        )

        candidates = engine.generate_email_candidates()

        self.assertIn("karri@linear.app", candidates)
        self.assertIn(
            "karri.saarinen@linear.app",
            candidates
        )


if __name__ == "__main__":
    unittest.main()
