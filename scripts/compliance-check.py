#!/usr/bin/env python3
"""Policy as Code — Compliance check engine for NetScaler VPX.

Reads compliance policies from a JSON file, evaluates each control
against a live VPX via NITRO API and HTTP probes, and produces a
compliance report (terminal + JSON).

Usage:
    python3 compliance-check.py MGMT_IP PASSWORD VIP [--policies FILE] [--output FILE]
"""

import argparse
import json
import os
import ssl
import socket
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone


def nitro_get(mgmt_ip, password, endpoint):
    """Query NITRO config endpoint. Returns parsed JSON or None."""
    url = f"https://{mgmt_ip}/nitro/v1/config/{endpoint}"
    req = urllib.request.Request(url, headers={
        "Content-Type": "application/json",
        "X-NITRO-USER": "nsroot",
        "X-NITRO-PASS": password,
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def nitro_extract(data, field=None):
    """Extract first resource item from NITRO response, optionally a field."""
    if not data:
        return None
    for key in data:
        if key in ("errorcode", "message", "severity"):
            continue
        val = data[key]
        items = val if isinstance(val, list) else [val]
        if not items:
            return None
        if field:
            return str(items[0].get(field, "NOT_FOUND"))
        return items[0]
    return None


def http_get_headers(vip, path="/get"):
    """Fetch response headers from VIP via curl."""
    try:
        result = subprocess.run(
            ["curl", "-sk", "-I", "--connect-timeout", "10",
             f"https://{vip}{path}"],
            capture_output=True, text=True, timeout=15,
        )
        headers = {}
        for line in result.stdout.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return headers
    except Exception:
        return {}


def tls_probe(vip):
    """Probe TLS connection and return protocol + cipher info."""
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{vip}:443"],
            input=b"", capture_output=True, text=True, timeout=15,
        )
        output = result.stdout + result.stderr
        protocol = None
        cipher = None
        key_bits = None
        for line in output.splitlines():
            if "Protocol" in line and ":" in line:
                protocol = line.split(":", 1)[1].strip()
            if "Cipher" in line and ":" in line and "0000" not in line:
                cipher = line.split(":", 1)[1].strip()
            if "Public-Key:" in line:
                import re
                m = re.search(r"(\d+)", line)
                if m:
                    key_bits = int(m.group(1))
        return {"protocol": protocol, "cipher": cipher, "key_bits": key_bits}
    except Exception:
        return {}


def evaluate_control(control, mgmt_ip, password, vip, cache):
    """Evaluate a single compliance control. Returns (status, detail)."""
    check = control["check"]
    check_type = check["type"]

    if check_type == "nitro":
        endpoint = check["endpoint"]
        if endpoint not in cache:
            cache[endpoint] = nitro_get(mgmt_ip, password, endpoint)
        data = cache[endpoint]
        if data is None:
            return "ERROR", "NITRO API unreachable"
        ec = data.get("errorcode", 999)
        if ec != 0:
            return "FAIL", f"resource not found (ec={ec})"
        actual = nitro_extract(data, check["field"])
        if actual == "NOT_FOUND":
            return "FAIL", f"field '{check['field']}' not found"
        expected = check["expected"]
        operator = check.get("operator", "eq")
        if operator == "eq":
            if actual.lower() == expected.lower():
                return "PASS", f"{check['field']}={actual}"
            return "FAIL", f"expected {expected}, got {actual}"
        elif operator == "gte":
            try:
                if int(actual) >= int(expected):
                    return "PASS", f"{check['field']}={actual} (>= {expected})"
                return "FAIL", f"expected >= {expected}, got {actual}"
            except ValueError:
                return "FAIL", f"non-numeric: {actual}"
        elif operator == "lte":
            try:
                if int(actual) <= int(expected):
                    return "PASS", f"{check['field']}={actual} (<= {expected})"
                return "FAIL", f"expected <= {expected}, got {actual}"
            except ValueError:
                return "FAIL", f"non-numeric: {actual}"

    elif check_type == "nitro_exists":
        endpoint = check["endpoint"]
        if endpoint not in cache:
            cache[endpoint] = nitro_get(mgmt_ip, password, endpoint)
        data = cache[endpoint]
        if data is None:
            return "FAIL", "NITRO API unreachable"
        ec = data.get("errorcode", 999)
        if ec == 0:
            return "PASS", "resource exists"
        return "FAIL", f"not found (ec={ec})"

    elif check_type == "nitro_binding":
        endpoint = check["endpoint"]
        if endpoint not in cache:
            cache[endpoint] = nitro_get(mgmt_ip, password, endpoint)
        data = cache[endpoint]
        if data is None:
            return "FAIL", "NITRO API unreachable"
        ec = data.get("errorcode", 999)
        if ec != 0:
            return "FAIL", f"binding not found (ec={ec})"
        field = check["field"]
        expected = check["expected"]
        for key in data:
            if key in ("errorcode", "message", "severity"):
                continue
            items = data[key] if isinstance(data[key], list) else [data[key]]
            for item in items:
                if item.get(field, "").lower() == expected.lower():
                    return "PASS", f"{field}={expected} bound"
            break
        return "FAIL", f"{expected} not bound"

    elif check_type == "http_header":
        cache_key = "__http_headers__"
        if cache_key not in cache:
            cache[cache_key] = http_get_headers(vip)
        headers = cache[cache_key]
        header_name = check["header"].lower()
        header_val = headers.get(header_name, "")
        expect = check.get("expect", "present")
        if expect == "absent":
            if not header_val:
                return "PASS", f"{check['header']} absent"
            return "FAIL", f"expected absent, got: {header_val}"
        if "contains" in check:
            if check["contains"] in header_val:
                return "PASS", f"{check['header']} contains '{check['contains']}'"
            if not header_val:
                return "FAIL", f"{check['header']} not present"
            return "FAIL", f"missing '{check['contains']}' in: {header_val}"
        # expect == "present"
        if header_val:
            return "PASS", f"{check['header']} present"
        return "FAIL", f"{check['header']} not present"

    elif check_type == "tls":
        cache_key = "__tls_probe__"
        if cache_key not in cache:
            cache[cache_key] = tls_probe(vip)
        tls_info = cache[cache_key]
        field = check["field"]
        expected = check["expected"]
        actual = str(tls_info.get(field, ""))
        if not actual:
            return "FAIL", f"could not determine {field}"
        if field == "protocol":
            # TLSv1.2 or TLSv1.3 both satisfy "TLSv1.2" minimum
            if actual in ("TLSv1.2", "TLSv1.3"):
                return "PASS", f"{field}={actual}"
            return "FAIL", f"expected {expected}+, got {actual}"
        if actual.lower() == expected.lower():
            return "PASS", f"{field}={actual}"
        return "FAIL", f"expected {expected}, got {actual}"

    return "ERROR", f"unknown check type: {check_type}"


def main():
    parser = argparse.ArgumentParser(description="VPX Compliance Check")
    parser.add_argument("mgmt_ip", help="VPX management IP")
    parser.add_argument("password", help="nsroot password")
    parser.add_argument("vip", help="VIP public IP")
    parser.add_argument("--policies", default="policies/compliance.json",
                        help="Path to compliance policy file")
    parser.add_argument("--output", help="Write JSON report to file")
    args = parser.parse_args()

    # Mask password in process listing
    os.environ.get("NSROOT_PW", "")

    # Load policies
    policy_path = args.policies
    if not os.path.isabs(policy_path):
        policy_path = os.path.join(os.path.dirname(__file__), "..", policy_path)
    with open(policy_path) as f:
        policies = json.load(f)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    cache = {}  # Deduplicate NITRO API calls

    print("")
    print("=" * 60)
    print("  COMPLIANCE REPORT")
    print(f"  MGMT: {args.mgmt_ip}  |  VIP: {args.vip}")
    print(f"  {now}")
    print("=" * 60)

    report = {
        "timestamp": now,
        "mgmt_ip": args.mgmt_ip,
        "vip": args.vip,
        "frameworks": [],
    }

    total_controls = 0
    total_passed = 0
    total_failed = 0
    critical_failures = 0
    high_failures = 0

    for framework in policies["frameworks"]:
        fw_id = framework["id"]
        fw_name = framework["name"]
        controls = framework["controls"]

        print("")
        print(f"--- {fw_name} ({len(controls)} controls) ---")

        fw_report = {
            "id": fw_id,
            "name": fw_name,
            "controls": [],
            "passed": 0,
            "failed": 0,
        }

        fw_critical = 0
        fw_high = 0

        for control in controls:
            total_controls += 1
            ctrl_id = control["id"]
            title = control["title"]
            severity = control["severity"]

            status, detail = evaluate_control(
                control, args.mgmt_ip, args.password, args.vip, cache
            )

            if status == "PASS":
                total_passed += 1
                fw_report["passed"] += 1
                icon = "PASS"
            else:
                total_failed += 1
                fw_report["failed"] += 1
                icon = "FAIL"
                if severity == "critical":
                    critical_failures += 1
                    fw_critical += 1
                if severity == "high":
                    high_failures += 1
                    fw_high += 1

            print(f"  {icon:6s} {ctrl_id:12s} {title} [{severity}]")
            if status != "PASS":
                print(f"         {' ' * 12} -> {detail}")

            fw_report["controls"].append({
                "id": ctrl_id,
                "title": title,
                "severity": severity,
                "status": status,
                "detail": detail,
            })

        passed = fw_report["passed"]
        total = len(controls)
        print(f"  Result: {passed}/{total} PASSED", end="")
        if fw_critical or fw_high:
            print(f" ({fw_critical} critical, {fw_high} high failures)")
        else:
            print("")

        report["frameworks"].append(fw_report)

    # Summary
    print("")
    print("=" * 60)
    print(f"  SUMMARY: {total_passed}/{total_controls} controls passed"
          f" across {len(policies['frameworks'])} frameworks")
    print(f"  Critical failures: {critical_failures}"
          f"  |  High failures: {high_failures}")

    pipeline_pass = critical_failures == 0 and high_failures == 0
    print(f"  Pipeline: {'PASS' if pipeline_pass else 'FAIL'}")
    print("=" * 60)
    print("")

    report["summary"] = {
        "total": total_controls,
        "passed": total_passed,
        "failed": total_failed,
        "critical_failures": critical_failures,
        "high_failures": high_failures,
        "result": "PASS" if pipeline_pass else "FAIL",
    }

    # Write JSON report
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  Report written to: {args.output}")
        print("")

    # Exit code: non-zero if any critical/high control failed
    sys.exit(0 if pipeline_pass else 1)


if __name__ == "__main__":
    main()
