import datetime
import unittest
import urllib.error

from validate_deployment import ValidationError, instance_urls, validate_instances


class DeploymentValidationTest(unittest.TestCase):
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    urls = ["https://one/api/v1", "https://two/api/v1"]

    def status(self, digest="a" * 64):
        return {"task_id": "GCRtest", "completed": True, "result": {
            "manifest_location": "s3://bucket/repo/_lakefs/run/manifest.json",
            "manifest_sha256": digest, "expires_at": "2026-01-02T00:00:00Z"}}

    def check(self, fetch):
        return validate_instances(self.urls, "owner", "GCRtest", "Basic test", fetch, lambda: self.now)

    def test_all_supplied_instances_are_checked_directly(self):
        requests = []

        def fetch(request):
            requests.append(request)
            return self.status()

        self.assertEqual(self.check(fetch), 2)
        self.assertEqual([r.host for r in requests], ["one", "two"])
        self.assertTrue(all(r.get_method() == "GET" for r in requests))

    def test_later_instance_fingerprint_rejection_fails_gate(self):
        def fetch(request):
            if request.host == "two":
                raise urllib.error.HTTPError(request.full_url, 409, "mapping mismatch", {}, None)
            return self.status()

        with self.assertRaisesRegex(ValidationError, "instance 2"):
            self.check(fetch)

    def test_different_manifest_fails_gate(self):
        with self.assertRaisesRegex(ValidationError, "different preparation"):
            self.check(lambda request: self.status(("a" if request.host == "one" else "b") * 64))

    def test_invalid_statuses_fail_gate(self):
        for modification in ({"completed": False}, {"result": None}, {"task_id": "other"},
                             {"error": {"message": "failed"}}):
            with self.subTest(modification=modification), self.assertRaises(ValidationError):
                self.check(lambda _: self.status() | modification)
        result = self.status()
        result["result"]["expires_at"] = "2025-12-31T00:00:00Z"
        with self.assertRaisesRegex(ValidationError, "expiry"):
            self.check(lambda _: result)

    def test_expiry_is_checked_after_each_response(self):
        expiry = datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc)
        moments = iter((self.now, expiry))
        with self.assertRaisesRegex(ValidationError, "instance 2.*expiry"):
            validate_instances(self.urls, "owner", "GCRtest", "Basic test",
                               lambda _: self.status(), lambda: next(moments))

    def test_expiry_is_checked_again_before_success(self):
        expiry = datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc)
        moments = iter((self.now, self.now, expiry))
        with self.assertRaisesRegex(ValidationError, "expired during deployment validation"):
            validate_instances(self.urls, "owner", "GCRtest", "Basic test",
                               lambda _: self.status(), lambda: next(moments))

    def test_instance_list_rejects_ambiguous_targets(self):
        self.assertEqual(instance_urls(["# comment", "https://one", "https://two/api/v1/"]), self.urls)
        for lines in ([], ["https://one", "https://one/api/v1"], ["https://user:secret@one"],
                      ["https://one?route=two"], ["https://one/path"]):
            with self.subTest(lines=lines), self.assertRaises(ValidationError):
                instance_urls(lines)


if __name__ == "__main__":
    unittest.main()
