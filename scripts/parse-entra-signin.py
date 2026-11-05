#!/usr/bin/env python3
"""
parse-entra-signin.py
Zero-dependency parser for Microsoft Entra ID (Azure AD) Sign-In JSON exports.
Extracts failed/interrupted sign-ins, evaluates applied Conditional Access policies,
highlights device/browser/IPv6 trust anomalies, and optionally anonymizes PII.

Usage:
    python parse-entra-signin.py --input SignIns.json --sanitize --format markdown
    Get-MgAuditLogSignIn -Top 1 | ConvertTo-Json | python parse-entra-signin.py -i -
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def mask_guid(val: str) -> str:
    if not val or not isinstance(val, str):
        return val
    digest = hashlib.sha256(val.encode("utf-8")).hexdigest()[:8]
    return f"00000000-0000-0000-0000-redacted{digest[:4]}"


def mask_ip(ip: str) -> str:
    if not ip or not isinstance(ip, str):
        return ip
    clean_ip = ip.strip("[]")
    if ":" in clean_ip:  # IPv6
        parts = clean_ip.split(":")
        prefix = ":".join(parts[:3]) if len(parts) >= 3 else parts[0]
        return f"{prefix}:xxxx:xxxx:xxxx:xxxx:xxxx (IPv6)"
    parts = clean_ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.xxx.xxx"
    return "xxx.xxx.xxx.xxx"


def mask_upn(upn: str) -> str:
    if not upn or not isinstance(upn, str) or "@" not in upn:
        return "user-redacted"
    digest = hashlib.sha256(upn.encode("utf-8")).hexdigest()[:6]
    return f"user-{digest}@corp.example.com"


def detect_anomalies(record: Dict[str, Any], failing_policies: List[Dict[str, Any]], sanitize: bool = False) -> List[Dict[str, str]]:
    """
    Evaluates runtime sign-in telemetry against known Conditional Access failure patterns.
    Returns a list of structured anomaly dicts with 'code', 'title', and 'description'.
    """
    anomalies: List[Dict[str, str]] = []
    device = record.get("deviceDetail") or {}
    raw_ip = record.get("ipAddress") or ""
    display_ip = mask_ip(raw_ip) if sanitize else raw_ip
    client_app = record.get("clientAppUsed") or ""
    browser = device.get("browser") or ""
    device_id = device.get("deviceId") or ""
    display_device_id = mask_guid(device_id) if sanitize else device_id
    display_device_name = "DEVICE-REDACTED" if sanitize else (device.get("displayName") or "Unknown")
    is_compliant = device.get("isCompliant")
    trust_type = device.get("trustType") or ""
    status = record.get("status") or {}
    error_code = status.get("errorCode", 0)

    # 1. Missing Device ID / PRT Passthrough in Desktop Browser
    for pol in failing_policies:
        grants = [g.lower() for g in (pol.get("enforcedGrantControls") or [])]
        if ("compliantdevice" in grants or "domainjoineddevice" in grants) and not device_id:
            anomalies.append({
                "code": "MISSING_PRT_OR_SSO_EXTENSION",
                "title": "Device ID Empty Under Compliant/DomainJoined Grant Requirement",
                "description": (
                    f"Device ID is empty while using browser '{browser}'. Entra cannot verify device compliance "
                    "or domain join without Primary Refresh Token (PRT) passthrough. Common causes: Google Chrome or "
                    "Mozilla Firefox missing Windows Accounts/Single Sign-On extension, Incognito/InPrivate mode "
                    "(which intentionally strips PRT), or macOS without Microsoft Enterprise SSO plug-in."
                ),
            })
            break

    # 2. IPv6 Address Evaluation Against IPv4-Only Named Locations
    clean_ip = raw_ip.strip("[]")
    if ":" in clean_ip:
        anomalies.append({
            "code": "IPV6_NAMED_LOCATION_MISMATCH",
            "title": "Dual-Stack IPv6 Address Used in Authentication",
            "description": (
                f"Sign-in originated from an IPv6 address ({display_ip}). If failing Conditional Access policies "
                "rely on Corporate Named Locations that only define IPv4 CIDR ranges, the user is evaluated "
                "as 'Outside Corporate Network' (Untrusted Location), triggering unintended blocks or MFA challenges."
            ),
        })

    # 3. Legacy Authentication Client Application
    legacy_clients = {
        "exchange activesync", "imap4", "pop3", "smtp", "other clients",
        "autodiscover", "mapi over http", "older office clients"
    }
    if client_app.lower() in legacy_clients:
        anomalies.append({
            "code": "LEGACY_AUTHENTICATION_PROTOCOL",
            "title": f"Legacy Protocol in Use: {client_app}",
            "description": (
                f"Client app '{client_app}' relies on legacy/basic authentication protocols. Legacy protocols "
                "cannot present MFA challenges or device claims, causing instant failure against modern CA policies "
                "or Security Defaults."
            ),
        })

    # 4. Registered Device Marked Non-Compliant (Compliance Drift)
    if device_id and is_compliant is False:
        anomalies.append({
            "code": "DEVICE_COMPLIANCE_DRIFT",
            "title": "Registered Device Evaluated as Non-Compliant",
            "description": (
                f"Device '{display_device_name}' (ID: {display_device_id}) is registered with Entra ID, "
                "but 'isCompliant' evaluated to False. Check Intune compliance status for OS build requirements, "
                "BitLocker encryption status, Defender ATP risk level, or overdue check-in."
            ),
        })

    # 5. Hybrid Entra Join Requirement Mismatch
    for pol in failing_policies:
        grants = [g.lower() for g in (pol.get("enforcedGrantControls") or [])]
        if "domainjoineddevice" in grants and trust_type.lower() != "serverad":
            anomalies.append({
                "code": "HYBRID_JOIN_MISMATCH",
                "title": f"Device Trust Type ({trust_type or 'None'}) Does Not Match Required Hybrid Join",
                "description": (
                    f"Policy '{pol.get('policyName')}' enforces 'DomainJoinedDevice' (Hybrid Entra Join / ServerAd), "
                    f"but device trust type is '{trust_type or 'Unregistered'}'. Workplace-joined or cloud-only Entra "
                    "joined devices will fail this grant control."
                ),
            })
            break

    # 6. Authentication Strength / Phishing-Resistant MFA Mismatch
    if error_code == 530034 or any("authenticationstrength" in str(pol).lower() for pol in failing_policies):
        anomalies.append({
            "code": "AUTHENTICATION_STRENGTH_MISMATCH",
            "title": "Authentication Strength (Phishing-Resistant MFA) Not Met",
            "description": (
                "The applied policy enforces an advanced Authentication Strength requirement (e.g. FIDO2 / Passkey, "
                "Windows Hello for Business, or Certificate-Based Authentication). The user's registered methods "
                "(such as SMS, Voice, or Authenticator Push) do not meet this tier."
            ),
        })

    # 7. Sign-In Frequency / CAE Token Expiration
    if error_code in (70043, 50058):
        anomalies.append({
            "code": "SESSION_CONTROL_REFRESH_FAILURE",
            "title": f"Silent Token Refresh Blocked (AADSTS{error_code})",
            "description": (
                f"Error code AADSTS{error_code} indicates a non-interactive silent token refresh failed due to "
                "Sign-In Frequency (SIF) session controls or Continuous Access Evaluation (CAE) policy re-evaluation."
            ),
        })

    return anomalies


def parse_records(raw_data: Any, include_success: bool, sanitize: bool) -> List[Dict[str, Any]]:
    if isinstance(raw_data, dict):
        if "value" in raw_data and isinstance(raw_data["value"], list):
            records = raw_data["value"]
        else:
            records = [raw_data]
    elif isinstance(raw_data, list):
        records = raw_data
    else:
        records = []

    parsed_list: List[Dict[str, Any]] = []

    for rec in records:
        if not isinstance(rec, dict):
            continue

        status = rec.get("status") or {}
        error_code = status.get("errorCode", 0)
        ca_status = (rec.get("conditionalAccessStatus") or "").lower()

        # By default filter to failures/interruptions
        if not include_success and error_code == 0 and ca_status not in ("failure", "notapplied"):
            continue

        ca_policies = rec.get("appliedConditionalAccessPolicies") or []
        failing_ca = []
        satisfied_ca = []

        for pol in ca_policies:
            if not isinstance(pol, dict):
                continue
            res = (pol.get("result") or "").lower()
            entry = {
                "policyName": pol.get("displayName", "Unnamed Policy"),
                "policyId": mask_guid(pol.get("id", "")) if sanitize else pol.get("id", ""),
                "result": pol.get("result", "unknown"),
                "enforcedGrantControls": pol.get("enforcedGrantControls") or [],
                "enforcedSessionControls": pol.get("enforcedSessionControls") or [],
                "conditionsSatisfied": pol.get("conditionsSatisfied"),
                "conditionsNotSatisfied": pol.get("conditionsNotSatisfied"),
            }
            if res in ("failure", "reportonlyfailure"):
                failing_ca.append(entry)
            elif res in ("success", "reportonlyinterrupted"):
                satisfied_ca.append(entry)

        device = rec.get("deviceDetail") or {}
        location = rec.get("location") or {}
        anomalies = detect_anomalies(rec, failing_ca, sanitize=sanitize)

        summary = {
            "createdDateTime": rec.get("createdDateTime"),
            "correlationId": mask_guid(rec.get("correlationId", "")) if sanitize else rec.get("correlationId"),
            "userPrincipalName": mask_upn(rec.get("userPrincipalName", "")) if sanitize else rec.get("userPrincipalName"),
            "userId": mask_guid(rec.get("userId", "")) if sanitize else rec.get("userId"),
            "appDisplayName": rec.get("appDisplayName"),
            "appId": mask_guid(rec.get("appId", "")) if sanitize else rec.get("appId"),
            "resourceDisplayName": rec.get("resourceDisplayName"),
            "isInteractive": rec.get("isInteractive", True),
            "clientAppUsed": rec.get("clientAppUsed"),
            "ipAddress": mask_ip(rec.get("ipAddress", "")) if sanitize else rec.get("ipAddress"),
            "location": f"{location.get('city', 'Unknown')}, {location.get('countryOrRegion', 'Unknown')}",
            "errorCode": error_code,
            "failureReason": status.get("failureReason") or "None (Success)",
            "additionalDetails": status.get("additionalDetails"),
            "conditionalAccessStatus": rec.get("conditionalAccessStatus"),
            "authenticationRequirement": rec.get("authenticationRequirement"),
            "deviceDetail": {
                "deviceId": mask_guid(device.get("deviceId", "")) if (sanitize and device.get("deviceId")) else device.get("deviceId", ""),
                "displayName": "DEVICE-REDACTED" if (sanitize and device.get("displayName")) else device.get("displayName", ""),
                "operatingSystem": device.get("operatingSystem"),
                "browser": device.get("browser"),
                "isCompliant": device.get("isCompliant"),
                "isManaged": device.get("isManaged"),
                "trustType": device.get("trustType"),
            },
            "failingConditionalAccessPolicies": failing_ca,
            "satisfiedConditionalAccessPolicies": satisfied_ca,
            "diagnosticHints": anomalies,
        }
        parsed_list.append(summary)

    return parsed_list


def format_markdown(parsed: List[Dict[str, Any]]) -> str:
    if not parsed:
        return "# Entra Sign-In Diagnostic Summary\n\nNo failed or interrupted sign-in events found in input dataset.\n"

    lines = [
        "# Entra ID Sign-In & Conditional Access Diagnostic Summary",
        f"**Total Events Extracted:** {len(parsed)}\n",
    ]

    for idx, item in enumerate(parsed, 1):
        dev = item["deviceDetail"]
        lines.append(f"## Event #{idx}: `{item['userPrincipalName']}` -> `{item['appDisplayName']}`")
        lines.append(f"- **Timestamp (UTC):** `{item['createdDateTime']}` | **Interactive:** `{item['isInteractive']}`")
        lines.append(f"- **Correlation ID:** `{item['correlationId']}`")
        lines.append(f"- **Error Code:** `AADSTS{item['errorCode']}` (`{item['errorCode']}`) - {item['failureReason']}")
        if item.get("additionalDetails"):
            lines.append(f"- **Additional Details:** {item['additionalDetails']}")
        lines.append(f"- **CA Status:** `{item['conditionalAccessStatus']}` | **Auth Requirement:** `{item['authenticationRequirement']}`")
        lines.append(f"- **Network & Client:** IP `{item['ipAddress']}` ({item['location']}) | Client: `{item['clientAppUsed']}`")
        lines.append(
            f"- **Device Context:** OS=`{dev['operatingSystem']}`, Browser=`{dev['browser']}`, "
            f"TrustType=`{dev['trustType']}`, Compliant=`{dev['isCompliant']}`, Managed=`{dev['isManaged']}`, "
            f"DeviceId Present=`{bool(dev['deviceId'])}`"
        )

        if item["failingConditionalAccessPolicies"]:
            lines.append("\n### Failing / Blocking Conditional Access Policies")
            lines.append("| Policy Name | Result | Enforced Grant Controls | Enforced Session Controls |")
            lines.append("| --- | --- | --- | --- |")
            for pol in item["failingConditionalAccessPolicies"]:
                grants = ", ".join(pol["enforcedGrantControls"]) or "None"
                sessions = ", ".join(pol["enforcedSessionControls"]) or "None"
                lines.append(f"| `{pol['policyName']}` | `{pol['result']}` | `{grants}` | `{sessions}` |")

        if item["diagnosticHints"]:
            lines.append("\n### Automated Root-Cause Anomaly Detections")
            for hint in item["diagnosticHints"]:
                lines.append(f"- **[{hint['code']}] {hint['title']}:** {hint['description']}")

        lines.append("\n---\n")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse and sanitize Entra ID Sign-In JSON logs for RCA.")
    parser.add_argument("-i", "--input", default="-", help="Path to exported Entra Sign-In JSON file, or '-' for stdin.")
    parser.add_argument("-f", "--format", choices=["markdown", "json"], default="markdown", help="Output format.")
    parser.add_argument("-s", "--sanitize", action="store_true", help="Anonymize UPNs, IPs, Device Names, and GUIDs.")
    parser.add_argument("--include-success", action="store_true", help="Include successful sign-ins in output.")
    parser.add_argument("-o", "--output", help="Optional output file path (prints to stdout if omitted).")

    args = parser.parse_args()

    # Read from file or stdin
    if args.input == "-" or not args.input:
        if sys.stdin.isatty():
            print("Error: No input file specified and no data piped via stdin.", file=sys.stderr)
            parser.print_help(sys.stderr)
            sys.exit(1)
        raw_text = sys.stdin.read()
    else:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Error: Input file not found: {input_path}", file=sys.stderr)
            sys.exit(1)
        raw_text = input_path.read_text(encoding="utf-8-sig")

    try:
        raw_data = json.loads(raw_text)
    except Exception as exc:
        print(f"Error: Failed to parse input as JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    parsed = parse_records(raw_data, include_success=args.include_success, sanitize=args.sanitize)

    if args.format == "json":
        output_text = json.dumps(parsed, indent=2)
    else:
        output_text = format_markdown(parsed)

    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Wrote {len(parsed)} parsed sign-in records to {args.output}", file=sys.stderr)
    else:
        print(output_text)


if __name__ == "__main__":
    main()
