#!/usr/bin/env python3
"""stress_test_entra_signin.py - 30-Scenario Stress & Edge-Case Battery for entra-signin-rca

Executes 30 rigorous edge-case, corruption, boundary, fuzzing, and performance tests
against parse-entra-signin.py to guarantee enterprise resilience.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict

# Resolve scripts path
BASE_DIR = Path(__file__).resolve().parent
REPO_DIR = BASE_DIR.parent
script_file = REPO_DIR / "scripts" / "parse-entra-signin.py"
if not script_file.exists():
    script_file = REPO_DIR / "skills" / "entra-signin-rca" / "scripts" / "parse-entra-signin.py"

import importlib.util
spec = importlib.util.spec_from_file_location("parse_entra_signin", str(script_file))
module = importlib.util.module_from_spec(spec)
sys.modules["parse_entra_signin"] = module
spec.loader.exec_module(module)

parse_records = module.parse_records
detect_anomalies = module.detect_anomalies
mask_ip = module.mask_ip
mask_upn = module.mask_upn
mask_guid = module.mask_guid


class TestSuite:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []

    def record(self, test_num: int, name: str, passed: bool, detail: str = ""):
        status = "PASS" if passed else "FAIL"
        if passed:
            self.passed += 1
        else:
            self.failed += 1
        self.results.append((test_num, name, status, detail))
        print(f"[{status}] Test {test_num:02d}: {name} {f'- {detail}' if detail else ''}")


def run_tests():
    suite = TestSuite()
    print("==================================================================")
    print("  entra-signin-rca Comprehensive 30-Scenario Stress Test Suite")
    print("==================================================================")

    # Test 01: Empty Input
    try:
        res = parse_records([], include_success=False, sanitize=False)
        suite.record(1, "Empty input list returns empty result cleanly", len(res) == 0)
    except Exception as exc:
        suite.record(1, "Empty input list", False, str(exc))

    # Test 02: Graph API Pagination Value Wrapper
    try:
        payload = {"@odata.nextLink": "https://graph.microsoft.com/...", "value": [{"status": {"errorCode": 50126}}]}
        res = parse_records(payload, include_success=False, sanitize=False)
        suite.record(2, "Graph API value wrapper unwrapped successfully", len(res) == 1)
    except Exception as exc:
        suite.record(2, "Graph API value wrapper", False, str(exc))

    # Test 03: Null Records in List
    try:
        payload = [None, {"status": {"errorCode": 50126}}, None, "invalid-record"]
        res = parse_records(payload, include_success=False, sanitize=False)
        suite.record(3, "Null and non-dict records in list skipped safely", len(res) == 1)
    except Exception as exc:
        suite.record(3, "Null records in list", False, str(exc))

    # Test 04: Missing Status Object
    try:
        payload = [{"id": "123", "userPrincipalName": "test@example.com", "conditionalAccessStatus": "failure"}]
        res = parse_records(payload, include_success=False, sanitize=False)
        suite.record(4, "Record missing status object handled with default code 0", len(res) == 1 and res[0]["errorCode"] == 0)
    except Exception as exc:
        suite.record(4, "Missing status object", False, str(exc))

    # Test 05: Fuzzed Non-Dict Device Detail
    try:
        payload = [{"status": {"errorCode": 53003}, "deviceDetail": "string-instead-of-dict"}]
        res = parse_records(payload, include_success=False, sanitize=False)
        suite.record(5, "Fuzzed string deviceDetail handled defensively without AttributeError", len(res) == 1)
    except Exception as exc:
        suite.record(5, "Fuzzed deviceDetail", False, str(exc))

    # Test 06: Fuzzed Non-Dict Location
    try:
        payload = [{"status": {"errorCode": 53003}, "location": 12345}]
        res = parse_records(payload, include_success=False, sanitize=False)
        suite.record(6, "Fuzzed integer location handled defensively without AttributeError", len(res) == 1)
    except Exception as exc:
        suite.record(6, "Fuzzed location", False, str(exc))

    # Test 07: Fuzzed Non-List CA Policies
    try:
        payload = [{"status": {"errorCode": 53003}, "appliedConditionalAccessPolicies": "not-a-list"}]
        res = parse_records(payload, include_success=False, sanitize=False)
        suite.record(7, "Fuzzed non-list appliedConditionalAccessPolicies handled safely", len(res) == 1)
    except Exception as exc:
        suite.record(7, "Fuzzed CA policies", False, str(exc))

    # Test 08: Missing Device ID Under Compliant Device Requirement
    try:
        record = {
            "clientAppUsed": "Browser",
            "deviceDetail": {"browser": "Chrome", "deviceId": ""},
            "status": {"errorCode": 53000}
        }
        failing_policies = [{"enforcedGrantControls": ["compliantDevice"], "policyName": "Require Compliant Device"}]
        anomalies = detect_anomalies(record, failing_policies)
        found = any(a["code"] == "MISSING_PRT_OR_SSO_EXTENSION" for a in anomalies)
        suite.record(8, "Desktop browser missing device ID under compliantDevice flags MISSING_PRT_OR_SSO_EXTENSION", found)
    except Exception as exc:
        suite.record(8, "Missing device ID", False, str(exc))

    # Test 09: Device ID Present Under Compliant Device Requirement
    try:
        record = {
            "clientAppUsed": "Browser",
            "deviceDetail": {"browser": "Edge", "deviceId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
            "status": {"errorCode": 53000}
        }
        failing_policies = [{"enforcedGrantControls": ["compliantDevice"], "policyName": "Require Compliant Device"}]
        anomalies = detect_anomalies(record, failing_policies)
        found = any(a["code"] == "MISSING_PRT_OR_SSO_EXTENSION" for a in anomalies)
        suite.record(9, "Browser with valid deviceId does not trigger missing PRT anomaly", not found)
    except Exception as exc:
        suite.record(9, "Device ID present", False, str(exc))

    # Test 10: Dual-Stack IPv6 Address Used in Authentication
    try:
        record = {"ipAddress": "2001:db8:85a3::8a2e:370:7334", "status": {"errorCode": 53003}}
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "IPV6_NAMED_LOCATION_MISMATCH" for a in anomalies)
        suite.record(10, "Dual-stack IPv6 sign-in flags IPV6_NAMED_LOCATION_MISMATCH against IPv4 named locations", found)
    except Exception as exc:
        suite.record(10, "IPv6 address evaluation", False, str(exc))

    # Test 11: Pure IPv4 Address Evaluation
    try:
        record = {"ipAddress": "198.51.100.45", "status": {"errorCode": 53003}}
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "IPV6_NAMED_LOCATION_MISMATCH" for a in anomalies)
        suite.record(11, "Standard IPv4 address does not trigger IPv6 mismatch anomaly", not found)
    except Exception as exc:
        suite.record(11, "Pure IPv4 evaluation", False, str(exc))

    # Test 12: Legacy Auth Protocol POP3
    try:
        record = {"clientAppUsed": "pop3", "status": {"errorCode": 53003}}
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "LEGACY_AUTHENTICATION_PROTOCOL" for a in anomalies)
        suite.record(12, "POP3 client detected and flagged as legacy basic authentication", found)
    except Exception as exc:
        suite.record(12, "Legacy auth POP3", False, str(exc))

    # Test 13: Legacy Auth Protocol IMAP4
    try:
        record = {"clientAppUsed": "imap4", "status": {"errorCode": 53003}}
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "LEGACY_AUTHENTICATION_PROTOCOL" for a in anomalies)
        suite.record(13, "IMAP4 client detected and flagged as legacy basic authentication", found)
    except Exception as exc:
        suite.record(13, "Legacy auth IMAP4", False, str(exc))

    # Test 14: Legacy Auth Protocol Exchange ActiveSync
    try:
        record = {"clientAppUsed": "exchange activesync", "status": {"errorCode": 53003}}
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "LEGACY_AUTHENTICATION_PROTOCOL" for a in anomalies)
        suite.record(14, "Exchange ActiveSync detected and flagged as legacy protocol", found)
    except Exception as exc:
        suite.record(14, "Legacy auth ActiveSync", False, str(exc))

    # Test 15: Modern Auth Browser
    try:
        record = {"clientAppUsed": "Browser", "status": {"errorCode": 53003}}
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "LEGACY_AUTHENTICATION_PROTOCOL" for a in anomalies)
        suite.record(15, "Modern browser client does not trigger legacy auth anomaly", not found)
    except Exception as exc:
        suite.record(15, "Modern auth browser", False, str(exc))

    # Test 16: Device Compliance Drift (isCompliant: False)
    try:
        record = {
            "deviceDetail": {"deviceId": "dev-12345", "isCompliant": False, "displayName": "CORP-LAPTOP-01"},
            "status": {"errorCode": 53000}
        }
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "DEVICE_COMPLIANCE_DRIFT" for a in anomalies)
        suite.record(16, "Device isCompliant=False flags DEVICE_COMPLIANCE_DRIFT", found)
    except Exception as exc:
        suite.record(16, "Compliance drift false", False, str(exc))

    # Test 17: Device Compliant (isCompliant: True)
    try:
        record = {
            "deviceDetail": {"deviceId": "dev-12345", "isCompliant": True, "displayName": "CORP-LAPTOP-01"},
            "status": {"errorCode": 0}
        }
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "DEVICE_COMPLIANCE_DRIFT" for a in anomalies)
        suite.record(17, "Device isCompliant=True does not trigger compliance drift", not found)
    except Exception as exc:
        suite.record(17, "Compliance drift true", False, str(exc))

    # Test 18: Hybrid Join Mismatch
    try:
        record = {
            "deviceDetail": {"trustType": "Workplace"},
            "status": {"errorCode": 53000}
        }
        failing_policies = [{"enforcedGrantControls": ["DomainJoinedDevice"], "policyName": "Require Hybrid Join"}]
        anomalies = detect_anomalies(record, failing_policies)
        found = any(a["code"] == "HYBRID_JOIN_MISMATCH" for a in anomalies)
        suite.record(18, "Workplace join under DomainJoinedDevice grant requirement flags HYBRID_JOIN_MISMATCH", found)
    except Exception as exc:
        suite.record(18, "Hybrid join mismatch", False, str(exc))

    # Test 19: Hybrid Join Satisfied (ServerAd)
    try:
        record = {
            "deviceDetail": {"trustType": "ServerAd"},
            "status": {"errorCode": 0}
        }
        failing_policies = [{"enforcedGrantControls": ["DomainJoinedDevice"], "policyName": "Require Hybrid Join"}]
        anomalies = detect_anomalies(record, failing_policies)
        found = any(a["code"] == "HYBRID_JOIN_MISMATCH" for a in anomalies)
        suite.record(19, "ServerAd device trust type satisfies hybrid join requirement without alert", not found)
    except Exception as exc:
        suite.record(19, "Hybrid join satisfied", False, str(exc))

    # Test 20: Authentication Strength Mismatch (Error 530034)
    try:
        record = {"status": {"errorCode": 530034}}
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "AUTHENTICATION_STRENGTH_MISMATCH" for a in anomalies)
        suite.record(20, "Error code AADSTS530034 flags AUTHENTICATION_STRENGTH_MISMATCH", found)
    except Exception as exc:
        suite.record(20, "Auth strength 530034", False, str(exc))

    # Test 21: Authentication Strength Keyword in Policy
    try:
        record = {"status": {"errorCode": 53003}}
        failing_policies = [{"policyName": "Phishing-Resistant AuthenticationStrength Policy", "enforcedGrantControls": []}]
        anomalies = detect_anomalies(record, failing_policies)
        found = any(a["code"] == "AUTHENTICATION_STRENGTH_MISMATCH" for a in anomalies)
        suite.record(21, "AuthenticationStrength keyword in policy flags auth tier requirement", found)
    except Exception as exc:
        suite.record(21, "Auth strength keyword", False, str(exc))

    # Test 22: Silent Token Refresh Blocked (AADSTS70043)
    try:
        record = {"status": {"errorCode": 70043}}
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "SESSION_CONTROL_REFRESH_FAILURE" for a in anomalies)
        suite.record(22, "Error AADSTS70043 flags SESSION_CONTROL_REFRESH_FAILURE (Sign-In Frequency expiration)", found)
    except Exception as exc:
        suite.record(22, "Session control 70043", False, str(exc))

    # Test 23: Silent Token Refresh Blocked (AADSTS50058)
    try:
        record = {"status": {"errorCode": 50058}}
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "SESSION_CONTROL_REFRESH_FAILURE" for a in anomalies)
        suite.record(23, "Error AADSTS50058 flags silent token refresh interruption", found)
    except Exception as exc:
        suite.record(23, "Session control 50058", False, str(exc))

    # Test 24: Password Spray / Invalid Credentials (AADSTS50126)
    try:
        record = {"status": {"errorCode": 50126}}
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "INVALID_CREDENTIALS_OR_SPRAY" for a in anomalies)
        suite.record(24, "Error AADSTS50126 flags INVALID_CREDENTIALS_OR_SPRAY", found)
    except Exception as exc:
        suite.record(24, "Password spray 50126", False, str(exc))

    # Test 25: Account Locked Out (AADSTS50053)
    try:
        record = {"status": {"errorCode": 50053}}
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "ACCOUNT_LOCKED_OUT" for a in anomalies)
        suite.record(25, "Error AADSTS50053 flags Smart Lockout ACCOUNT_LOCKED_OUT", found)
    except Exception as exc:
        suite.record(25, "Account lockout 50053", False, str(exc))

    # Test 26: Explicit Conditional Access Block (AADSTS53003)
    try:
        record = {"status": {"errorCode": 53003}, "clientAppUsed": "MobileApp", "ipAddress": "198.51.100.1"}
        anomalies = detect_anomalies(record, [])
        found = any(a["code"] == "CONDITIONAL_ACCESS_BLOCK_POLICY" for a in anomalies)
        suite.record(26, "Error AADSTS53003 isolated as CONDITIONAL_ACCESS_BLOCK_POLICY", found)
    except Exception as exc:
        suite.record(26, "Explicit block 53003", False, str(exc))

    # Test 27: UPN Sanitization for B2B External Guest
    try:
        masked = mask_upn("external_consultant_gmail.com#EXT#@mycompany.onmicrosoft.com")
        valid = masked.startswith("user-") and "external_consultant" not in masked and "gmail.com" not in masked
        suite.record(27, "B2B external guest account UPN safely masked with SHA-256", valid)
    except Exception as exc:
        suite.record(27, "B2B UPN sanitization", False, str(exc))

    # Test 28: IP Sanitization with Port Attached
    try:
        masked = mask_ip("203.0.113.88:8443")
        valid = masked.startswith("192.0.2.") and "8443" not in masked and "203.0.113" not in masked
        suite.record(28, "Port-attached IPv4 address parsed and mapped to RFC 5737 test address", valid)
    except Exception as exc:
        suite.record(28, "IP with port sanitization", False, str(exc))

    # Test 29: Include Success Flag
    try:
        records = [
            {"status": {"errorCode": 0}, "conditionalAccessStatus": "success"},
            {"status": {"errorCode": 50126}, "conditionalAccessStatus": "failure"}
        ]
        res_default = parse_records(records, include_success=False, sanitize=False)
        res_all = parse_records(records, include_success=True, sanitize=False)
        suite.record(29, "include_success=True preserves successful sign-ins, default filters to failures", len(res_default) == 1 and len(res_all) == 2)
    except Exception as exc:
        suite.record(29, "Include success flag", False, str(exc))

    # Test 30: High-Volume Performance Benchmark (10,000 Sign-In Events)
    try:
        large_records = [
            {
                "createdDateTime": "2026-11-05T12:00:00Z",
                "correlationId": f"00000000-0000-0000-0000-{i:012d}",
                "userPrincipalName": f"user{i}@corp.example.com",
                "status": {"errorCode": 50126 if i % 10 == 0 else 53003},
                "conditionalAccessStatus": "failure",
                "clientAppUsed": "Browser",
                "deviceDetail": {"browser": "Edge", "isCompliant": False, "deviceId": f"dev-{i}"},
                "appliedConditionalAccessPolicies": [{"policyName": "Require Compliance", "result": "failure"}]
            }
            for i in range(10000)
        ]
        start = time.perf_counter()
        parsed = parse_records(large_records, include_success=False, sanitize=True)
        elapsed = time.perf_counter() - start
        suite.record(30, f"High-volume sign-in benchmark (10,000 events in {elapsed:.3f}s)", elapsed < 1.0, f"Throughput: {10000/elapsed:,.0f} records/sec")
    except Exception as exc:
        suite.record(30, "High-volume benchmark", False, str(exc))

    print("==================================================================")
    print(f"  STRESS TEST SUMMARY: {suite.passed} PASSED, {suite.failed} FAILED out of 30 tests")
    print("==================================================================")

    if suite.failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
