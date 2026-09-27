#!/usr/bin/env python3
"""Validate one completed GC preparation directly against all supplied servers.

The deployment must provide a complete instance list. This tool does not discover
servers or prove that legacy collectors have been retired. It never starts GC.
"""

import argparse
import base64
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


class ValidationError(Exception):
    """The supplied deployment cannot validate this preparation."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValidationError("instance redirected the validation request")


def instance_urls(lines):
    urls = []
    for line in lines:
        value = line.strip().rstrip("/")
        if not value or value.startswith("#"):
            continue
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/api/v1")):
            raise ValidationError("instance URLs must be HTTP(S) origins, optionally ending in /api/v1")
        if parsed.path == "":
            value += "/api/v1"
        if value in urls:
            raise ValidationError("duplicate instance URL")
        urls.append(value)
    if not urls:
        raise ValidationError("the instance list is empty")
    return urls


def completed_result(status, task_id, now):
    if not isinstance(status, dict):
        raise ValidationError("status response is not an object")
    if status.get("task_id") != task_id or status.get("completed") is not True:
        raise ValidationError("preparation is missing, mismatched or incomplete")
    if status.get("error") is not None:
        raise ValidationError("preparation failed")
    result = status.get("result")
    if not isinstance(result, dict):
        raise ValidationError("successful preparation has no result")
    location = result.get("manifest_location")
    digest = result.get("manifest_sha256")
    if not isinstance(location, str) or not location:
        raise ValidationError("manifest location is missing")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValidationError("manifest digest is invalid")
    try:
        expiry = datetime.datetime.fromisoformat(result["expires_at"].replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= now:
            raise ValueError("expired or missing timezone")
    except (KeyError, AttributeError, TypeError, ValueError) as exc:
        raise ValidationError("preparation expiry is invalid or elapsed") from exc
    return location, digest, expiry


def validate_instances(urls, repository, task_id, authorization, fetch=None, clock=None):
    if clock is None:
        clock = lambda: datetime.datetime.now(datetime.timezone.utc)
    if fetch is None:
        opener = urllib.request.build_opener(NoRedirect())

        def fetch(request):
            with opener.open(request, timeout=30) as response:
                # A status response has bounded scalar fields, not a manifest payload.
                payload = response.read(1024 * 1024 + 1)
                if len(payload) > 1024 * 1024:
                    raise ValidationError("status response exceeds size limit")
                return json.loads(payload)

    expected = None
    for index, base in enumerate(urls, start=1):
        endpoint = (base + "/repositories/" + urllib.parse.quote(repository, safe="")
                    + "/gc/prepare_references/status?" + urllib.parse.urlencode({"id": task_id}))
        request = urllib.request.Request(endpoint, headers={"Authorization": authorization})
        try:
            result = completed_result(fetch(request), task_id, clock())
        except (urllib.error.URLError, ValueError, TypeError, ValidationError) as exc:
            raise ValidationError(f"instance {index} did not validate the preparation: {exc}") from exc
        if expected is None:
            expected = result
        elif result != expected:
            raise ValidationError(f"instance {index} returned a different preparation binding")
    if expected is not None and expected[2] <= clock():
        raise ValidationError("preparation expired during deployment validation")
    return len(urls)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instances-file", required=True, help="one direct serving-instance URL per line")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--task-id", required=True, help="completed prepare_references task")
    args = parser.parse_args()
    try:
        access = os.environ["LAKEFS_ACCESS_KEY_ID"]
        secret = os.environ["LAKEFS_SECRET_ACCESS_KEY"]
        if not access or not secret:
            raise ValidationError("lakeFS credential environment variables must not be empty")
        authorization = "Basic " + base64.b64encode(f"{access}:{secret}".encode()).decode()
        with open(args.instances_file, encoding="utf-8") as stream:
            urls = instance_urls(stream)
        count = validate_instances(urls, args.repository, args.task_id, authorization)
    except (KeyError, OSError, ValidationError) as exc:
        print(f"GC deployment validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Validated the same completed preparation on {count} supplied instances.")
    print("The deployment remains responsible for a complete instance list and retirement of legacy collectors and reports.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
