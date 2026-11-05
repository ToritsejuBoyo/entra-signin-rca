#!/usr/bin/env python3
"""
validate-skill.py
Automated test suite and validator for entra-signin-rca.
Executes parse-entra-signin.py against all synthetic fixtures and verifies:
1. Deterministic anomaly detection accuracy
2. PII sanitization integrity (UPNs, IPs, GUIDs masked)
3. Output format stability (JSON and Markdown)
4. Stdin pipeline support
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PARSER_SCRIPT = REPO_ROOT / "scripts" / "parse-entra-signin.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"


def run_parser(args: list, stdin_input: str = None) -> tuple[int, str, str]:
    cmd = [sys.executable, str(PARSER_SCRIPT)] + args
    res = subprocess.run(
        cmd,
        input=stdin_input,
        text=True,
        capture_output=True,
        cwd=str(REPO_ROOT),
    )
    return res.returncode, res.stdout, res.stderr


def test_fixture_device_compliance():
    fixture = FIXTURES_DIR / "fixture-ca-device-not-compliant.json"
    code, stdout, stderr = run_parser(["-i", str(fixture), "-f", "json"])
    assert code == 0, f"Parser failed on device compliance fixture: {stderr}"
    data = json.loads(stdout)
    assert len(data) == 1
    event = data[0]
    assert event["errorCode"] == 53003
    assert len(event["failingConditionalAccessPolicies"]) == 1
    assert event["failingConditionalAccessPolicies"][0]["policyName"] == "CA001-Require-Compliant-Device-For-Office365"
    
    anomaly_codes = [a["code"] for a in event["diagnosticHints"]]
    assert "MISSING_PRT_OR_SSO_EXTENSION" in anomaly_codes, f"Expected MISSING_PRT_OR_SSO_EXTENSION in {anomaly_codes}"
    print("[PASS] Fixture 1: Device Compliance & Missing PRT in Browser verified.")


def test_fixture_ipv6_named_location():
    fixture = FIXTURES_DIR / "fixture-ca-ipv6-named-location-block.json"
    code, stdout, stderr = run_parser(["-i", str(fixture), "-f", "json"])
    assert code == 0, f"Parser failed on IPv6 fixture: {stderr}"
    data = json.loads(stdout)
    assert len(data) == 1
    event = data[0]
    assert event["errorCode"] == 53003
    assert event["failingConditionalAccessPolicies"][0]["policyName"] == "CA002-Block-Untrusted-Locations-For-Corporate-Apps"
    
    anomaly_codes = [a["code"] for a in event["diagnosticHints"]]
    assert "IPV6_NAMED_LOCATION_MISMATCH" in anomaly_codes, f"Expected IPV6_NAMED_LOCATION_MISMATCH in {anomaly_codes}"
    print("[PASS] Fixture 2: IPv6 Named Location Mismatch verified.")


def test_fixture_auth_strength_mismatch():
    fixture = FIXTURES_DIR / "fixture-ca-auth-strength-mismatch.json"
    code, stdout, stderr = run_parser(["-i", str(fixture), "-f", "json"])
    assert code == 0, f"Parser failed on auth strength fixture: {stderr}"
    data = json.loads(stdout)
    assert len(data) == 1
    event = data[0]
    assert event["errorCode"] == 530034
    assert event["failingConditionalAccessPolicies"][0]["policyName"] == "CA003-Require-Phishing-Resistant-MFA-For-Privileged-Roles"
    
    anomaly_codes = [a["code"] for a in event["diagnosticHints"]]
    assert "AUTHENTICATION_STRENGTH_MISMATCH" in anomaly_codes, f"Expected AUTHENTICATION_STRENGTH_MISMATCH in {anomaly_codes}"
    print("[PASS] Fixture 3: Authentication Strength Mismatch verified.")


def test_fixture_legacy_auth():
    fixture = FIXTURES_DIR / "fixture-ca-legacy-auth-block.json"
    code, stdout, stderr = run_parser(["-i", str(fixture), "-f", "json"])
    assert code == 0, f"Parser failed on legacy auth fixture: {stderr}"
    data = json.loads(stdout)
    assert len(data) == 1
    event = data[0]
    assert event["clientAppUsed"] == "Exchange ActiveSync"
    assert event["failingConditionalAccessPolicies"][0]["policyName"] == "CA004-Block-Legacy-Authentication"
    
    anomaly_codes = [a["code"] for a in event["diagnosticHints"]]
    assert "LEGACY_AUTHENTICATION_PROTOCOL" in anomaly_codes, f"Expected LEGACY_AUTHENTICATION_PROTOCOL in {anomaly_codes}"
    print("[PASS] Fixture 4: Legacy Authentication Protocol Block verified.")


def test_sanitization_integrity():
    fixture = FIXTURES_DIR / "fixture-ca-ipv6-named-location-block.json"
    code, stdout, stderr = run_parser(["-i", str(fixture), "-f", "json", "--sanitize"])
    assert code == 0, f"Sanitization test failed: {stderr}"
    data = json.loads(stdout)
    event = data[0]
    
    # Check that real UPN, IP, and GUID are masked
    assert "marcus.vance@contoso.com" not in stdout, "Real UPN leaked into sanitized output"
    assert "user-" in event["userPrincipalName"] and "@corp.example.com" in event["userPrincipalName"]
    assert "2600:1700:4590:1200:d1b2:48f9:8234:5512" not in stdout, "Real IPv6 leaked into sanitized output"
    assert "xxxx:xxxx" in event["ipAddress"]
    assert "5a4178cc-3120-4ee1-b998-1123456789ab" not in stdout, "Real Device ID leaked into sanitized output"
    assert event["deviceDetail"]["displayName"] == "DEVICE-REDACTED"
    print("[PASS] Sanitization Integrity: PII and telemetry identifiers fully masked.")


def test_markdown_formatting():
    fixture = FIXTURES_DIR / "fixture-ca-device-not-compliant.json"
    code, stdout, stderr = run_parser(["-i", str(fixture), "-f", "markdown", "--sanitize"])
    assert code == 0, f"Markdown formatting failed: {stderr}"
    assert "# Entra ID Sign-In & Conditional Access Diagnostic Summary" in stdout
    assert "Failing / Blocking Conditional Access Policies" in stdout
    assert "Automated Root-Cause Anomaly Detections" in stdout
    assert "CA001-Require-Compliant-Device-For-Office365" in stdout
    print("[PASS] Markdown Output: Structured report generated cleanly.")


def test_stdin_pipeline():
    fixture = FIXTURES_DIR / "fixture-ca-legacy-auth-block.json"
    raw_content = fixture.read_text(encoding="utf-8")
    code, stdout, stderr = run_parser(["-i", "-", "-f", "json"], stdin_input=raw_content)
    assert code == 0, f"Stdin pipeline failed: {stderr}"
    data = json.loads(stdout)
    assert len(data) == 1
    assert data[0]["clientAppUsed"] == "Exchange ActiveSync"
    print("[PASS] Stdin Pipeline: Piped data stream parsed successfully.")


def main():
    print("=" * 60)
    print("Running Automated Test Suite for entra-signin-rca")
    print("=" * 60)

    try:
        test_fixture_device_compliance()
        test_fixture_ipv6_named_location()
        test_fixture_auth_strength_mismatch()
        test_fixture_legacy_auth()
        test_sanitization_integrity()
        test_markdown_formatting()
        test_stdin_pipeline()
        print("=" * 60)
        print("ALL TESTS PASSED (7/7 suites successful)")
        print("=" * 60)
        return 0
    except AssertionError as exc:
        print(f"\n[FAIL] Test assertion failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"\n[ERROR] Unexpected error during validation: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
