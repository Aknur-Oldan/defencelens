import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

def request(url, token, method="GET", body=None, content_type=None):
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", "Bearer " + token)
    if content_type:
        req.add_header("Content-Type", content_type)
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.loads(response.read())

def upload(api, token, path):
    boundary = uuid.uuid4().hex
    with open(path, "rb") as handle:
        content = handle.read()
    name = os.path.basename(path)
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return request(f"{api}/api/scans", token, "POST", body, f"multipart/form-data; boundary={boundary}")

def main():
    parser = argparse.ArgumentParser(description="DefenceLens deployment policy gate. Exit codes: 0 pass, 1 fail, 2 error.")
    parser.add_argument("--api", default=os.environ.get("DEFENCELENS_API", "http://localhost:18000"))
    parser.add_argument("--token", default=os.environ.get("API_TOKEN", ""))
    parser.add_argument("--scan-id", help="Evaluate an existing scan")
    parser.add_argument("--image", help="Upload an uncompressed docker save archive, scan it, then evaluate")
    parser.add_argument("--timeout", type=int, default=900, help="Seconds to wait for scan completion")
    args = parser.parse_args()
    if not args.token:
        print("ERROR: API token is required (--token or API_TOKEN).")
        return 2
    if bool(args.scan_id) == bool(args.image):
        print("ERROR: provide exactly one of --scan-id or --image.")
        return 2
    try:
        scan_id = args.scan_id
        if args.image:
            scan = upload(args.api, args.token, args.image)
            scan_id = scan["id"]
            print(f"Uploaded {args.image}: scan {scan_id}")
        deadline = time.monotonic() + args.timeout
        while True:
            scan = request(f"{args.api}/api/scans/{scan_id}", args.token)
            if scan["status"] in ("completed", "failed"):
                break
            if time.monotonic() > deadline:
                print(f"ERROR: scan did not finish within {args.timeout}s (status: {scan['status']}). A timed-out scan is not a passed check.")
                return 2
            print(f"Waiting: scan status is {scan['status']}")
            time.sleep(5)
        verdict = request(f"{args.api}/api/scans/{scan_id}/policy", args.token)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:500]
        print(f"ERROR: API returned {exc.code}: {detail}")
        return 2
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}")
        return 2
    print(f"Image: {verdict.get('filename')} (digest {str(verdict.get('digest'))[:16]}…)")
    print(f"Policy: max CRITICAL {verdict['policy']['max_critical']}, max HIGH {verdict['policy']['max_high']}, "
          f"secrets blocking: {verdict['policy']['fail_on_secrets']}")
    for reason in verdict["reasons"]:
        print(f"- {reason}")
    print(f"Outcome: {verdict['outcome'].upper()}")
    return {"pass": 0, "fail": 1}.get(verdict["outcome"], 2)

if __name__ == "__main__":
    sys.exit(main())
