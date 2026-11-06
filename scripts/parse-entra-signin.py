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

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _safe_dict(val: Any) -> Dict[str, Any]:
    return val if isinstance(val, dict) else {}


def _safe_list(val: Any) -> List[Any]:
    return val if isinstance(val, list) else []


def _safe_str(val: Any, default: str = "") -> str:
    if val is None:
        return default
    return str(val).strip()


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def mask_guid(val: Any) -> str:
    if not val:
        return ""
    val_str = str(val).strip()
    if not val_str:
        return ""
    digest = hashlib.sha256(val_str.encode("utf-8")).hexdigest()[:8]
    return f"00000000-0000-0000-0000-redacted{digest[:4]}"


def mask_ip(ip: Any) -> str:
    if not ip:
        return ""
    clean_ip = str(ip).strip()
    # Strip port if bracketed IPv6: [2001:db8::1]:8080 or [fe80::1]
    m_v6 = re.match(r"^\[([0-9a-fA-F:]+)\](?::\d+)?$", clean_ip)
    if m_v6:
        clean_ip = m_v6.group(1)
    else:
        # Strip port if IPv4 with port: 198.51.100.1:443
        m_v4 = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?$", clean_ip)
        if m_v4:
            clean_ip = m_v4.group(1)
        else:
            clean_ip = clean_ip.strip("[]")

    if ":" in clean_ip:  # IPv6
        parts = clean_ip.split(":")
        prefix = ":".join(parts[:3]) if len(parts) >= 3 else parts[0]
        return f"{prefix}:xxxx:xxxx:xxxx:xxxx:xxxx (IPv6)"

    parts = clean_ip.split(".")
    if len(parts) == 4:
        try:
            last = int(parts[3]) % 254 + 1
        except ValueError:
            last = 10
        return f"192.0.2.{last}"
    return "192.0.2.1"


def mask_upn(upn: Any) -> str:
    if not upn:
        return "user-redacted@corp.example.com"
    val = str(upn).strip()
    if "@" in val:
        digest = hashlib.sha256(val.encode("utf-8")).hexdigest()[:6]
        return f"user-{digest}@corp.example.com"
    # Phone or guest ID
    digest = hashlib.sha256(val.encode("utf-8")).hexdigest()[:6]
    return f"user-{digest}@corp.example.com"


def detect_anomalies(record: Dict[str, Any], failing_policies: List[Dict[str, Any]], sanitize: bool = False) -> List[Dict[str, str]]:
    """
    Evaluates runtime sign-in telemetry against known Conditional Access failure patterns.
    Returns a list of structured anomaly dicts with 'code', 'title', and 'description'.
    """
    anomalies: List[Dict[str, str]] = []
    device = _safe_dict(record.get("deviceDetail"))
    raw_ip = _safe_str(record.get("ipAddress"))
    display_ip = mask_ip(raw_ip) if sanitize else raw_ip
    client_app = _safe_str(record.get("clientAppUsed"))
    browser = _safe_str(device.get("browser"))
    device_id = _safe_str(device.get("deviceId"))
    display_device_id = mask_guid(device_id) if sanitize else device_id
    display_device_name = "DEVICE-REDACTED" if sanitize else (_safe_str(device.get("displayName")) or "Unknown")
    is_compliant = device.get("isCompliant")
    trust_type = _safe_str(device.get("trustType"))
    status = _safe_dict(record.get("status"))
    error_code = _safe_int(status.get("errorCode", 0))

    # 1. Missing Device ID / PRT Passthrough in Desktop Browser
    for pol in failing_policies:
        pol_dict = _safe_dict(pol)
        grants = [str(g).lower() for g in _safe_list(pol_dict.get("enforcedGrantControls")) if g]
        if ("compliantdevice" in grants or "domainjoineddevice" in grants) and not device_id:
            anomalies.append({
                "code": "MISSING_PRT_OR_SSO_EXTENSION",
                "title": "Device ID Empty Under Compliant/DomainJoined Grant Requirement",
                "description": (
                    f"Device ID is empty while using browser '{browser or 'Unknown'}'. Entra cannot verify device compliance "
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
        pol_dict = _safe_dict(pol)
        grants = [str(g).lower() for g in _safe_list(pol_dict.get("enforcedGrantControls")) if g]
        if "domainjoineddevice" in grants and trust_type.lower() != "serverad":
            anomalies.append({
                "code": "HYBRID_JOIN_MISMATCH",
                "title": f"Device Trust Type ({trust_type or 'None'}) Does Not Match Required Hybrid Join",
                "description": (
                    f"Policy '{pol_dict.get('policyName')}' enforces 'DomainJoinedDevice' (Hybrid Entra Join / ServerAd), "
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

    # 8. Password Spray / Invalid Credentials
    if error_code == 50126:
        anomalies.append({
            "code": "INVALID_CREDENTIALS_OR_SPRAY",
            "title": "Invalid Username or Password (AADSTS50126)",
            "description": "Sign-in failed due to invalid credentials. Frequent occurrences indicate user typo or automated brute-force / password spray attack.",
        })

    # 9. Account Lockout
    if error_code == 50053:
        anomalies.append({
            "code": "ACCOUNT_LOCKED_OUT",
            "title": "Account Locked Out (AADSTS50053)",
            "description": "Account is locked because user tried to sign in too many times with an incorrect user ID or password. Smart Lockout triggered.",
        })

    # 10. Explicit Conditional Access Block
    if error_code == 53003 and not any(a["code"] in ("LEGACY_AUTHENTICATION_PROTOCOL", "IPV6_NAMED_LOCATION_MISMATCH") for a in anomalies):
        anomalies.append({
            "code": "CONDITIONAL_ACCESS_BLOCK_POLICY",
            "title": "Access Blocked by Conditional Access Policy (AADSTS53003)",
            "description": "Sign-in was evaluated against an explicit block policy (e.g. untrusted location, untrusted platform, or non-compliant client).",
        })

    # 11. Multi-Factor Authentication Challenge Required
    if error_code in (50076, 50074):
        anomalies.append({
            "code": "MFA_CHALLENGE_REQUIRED",
            "title": f"MFA Challenge Required by Tenant Policy (AADSTS{error_code})",
            "description": (
                f"Error code AADSTS{error_code} indicates primary authentication succeeded, but an active policy "
                "or location change requires Multi-Factor Authentication (MFA). Common in background sync agents, "
                "rich clients, or non-interactive sessions unable to render the interactive MFA prompt."
            ),
        })

    # 12. MFA Registration Enrollment Required
    if error_code in (50079, 50072):
        anomalies.append({
            "code": "MFA_REGISTRATION_REQUIRED",
            "title": f"User Must Enroll in Multi-Factor Authentication (AADSTS{error_code})",
            "description": (
                f"Error code AADSTS{error_code} indicates the user account has no registered MFA methods "
                "(such as Microsoft Authenticator, FIDO2 passkey, or phone). The user must visit https://aka.ms/mfasetup "
                "from a trusted network to complete security info registration."
            ),
        })

    # 13. Identity Protection Risk Detected
    risk_level = _safe_str(record.get("riskLevelDuringSignIn") or record.get("riskLevelAggregated")).lower()
    risk_detail = _safe_str(record.get("riskDetail", "none"))
    risk_state = _safe_str(record.get("riskState", "none")).lower()
    if risk_level in ("high", "medium") or risk_state in ("atrisk", "confirmedcompromised"):
        anomalies.append({
            "code": "IDENTITY_PROTECTION_RISK_DETECTED",
            "title": f"Identity Protection {risk_level.capitalize()} Risk Flagged",
            "description": (
                f"Microsoft Entra ID Protection detected '{risk_level}' risk level on this sign-in "
                f"(Detail: {risk_detail}, State: {risk_state}). Risk-based Conditional Access policies "
                "automatically enforce step-up MFA, self-service password reset, or immediate session blocks."
            ),
        })

    # 14. Mobile Application Management (MAM) App Protection Policy Required
    for pol in failing_policies:
        pol_dict = _safe_dict(pol)
        grants = [str(g).lower() for g in _safe_list(pol_dict.get("enforcedGrantControls")) if g]
        if "approvedapplication" in grants or "compliantapplication" in grants:
            anomalies.append({
                "code": "MAM_APP_PROTECTION_REQUIRED",
                "title": f"Approved Client App / App Protection Policy Required by '{pol_dict.get('policyName')}'",
                "description": (
                    f"Policy '{pol_dict.get('policyName')}' enforces 'Require approved client app' or 'Require app protection policy' (Intune MAM). "
                    f"Client application '{client_app or 'Unknown'}' is not an Intune MAM-enlightened app. "
                    "User must access Microsoft 365 services via managed Outlook, OneDrive, or Edge with Intune app protection active."
                ),
            })
            break

    # 15. Terms of Use Consent Acceptance Required
    for pol in failing_policies:
        pol_dict = _safe_dict(pol)
        grants = [str(g).lower() for g in _safe_list(pol_dict.get("enforcedGrantControls")) if g]
        if "termsofuse" in grants or error_code == 50158:
            anomalies.append({
                "code": "TERMS_OF_USE_NOT_ACCEPTED",
                "title": f"Terms of Use Consent Required by '{pol_dict.get('policyName')}'",
                "description": (
                    f"Policy '{pol_dict.get('policyName')}' requires accepting an organizational Terms of Use agreement. "
                    "If signing in from a non-interactive client, mobile mail app, or embedded protocol, the web consent modal cannot display."
                ),
            })
            break

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

        status = _safe_dict(rec.get("status"))
        error_code = _safe_int(status.get("errorCode", 0))
        ca_status = _safe_str(rec.get("conditionalAccessStatus")).lower()

        # By default filter to failures/interruptions
        if not include_success and error_code == 0 and ca_status not in ("failure", "notapplied"):
            continue

        ca_policies = _safe_list(rec.get("appliedConditionalAccessPolicies"))
        failing_ca = []
        satisfied_ca = []

        for pol in ca_policies:
            if not isinstance(pol, dict):
                continue
            res = _safe_str(pol.get("result")).lower()
            entry = {
                "policyName": _safe_str(pol.get("displayName", "Unnamed Policy")),
                "policyId": mask_guid(pol.get("id", "")) if sanitize else _safe_str(pol.get("id")),
                "result": _safe_str(pol.get("result", "unknown")),
                "enforcedGrantControls": [str(g) for g in _safe_list(pol.get("enforcedGrantControls")) if g],
                "enforcedSessionControls": [str(s) for s in _safe_list(pol.get("enforcedSessionControls")) if s],
                "conditionsSatisfied": pol.get("conditionsSatisfied"),
                "conditionsNotSatisfied": pol.get("conditionsNotSatisfied"),
            }
            if res in ("failure", "reportonlyfailure"):
                failing_ca.append(entry)
            elif res in ("success", "reportonlyinterrupted"):
                satisfied_ca.append(entry)

        device = _safe_dict(rec.get("deviceDetail"))
        location = _safe_dict(rec.get("location"))
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
            "riskLevelDuringSignIn": rec.get("riskLevelDuringSignIn"),
            "riskDetail": rec.get("riskDetail"),
            "riskState": rec.get("riskState"),
            "errorCode": error_code,
            "failureReason": status.get("failureReason") or "None (Success)",
            "additionalDetails": status.get("additionalDetails"),
            "conditionalAccessStatus": rec.get("conditionalAccessStatus"),
            "authenticationRequirement": rec.get("authenticationRequirement"),
            "deviceDetail": {
                "deviceId": mask_guid(device.get("deviceId", "")) if (sanitize and device.get("deviceId")) else _safe_str(device.get("deviceId")),
                "displayName": "DEVICE-REDACTED" if (sanitize and device.get("displayName")) else _safe_str(device.get("displayName")),
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
        dev = _safe_dict(item.get("deviceDetail"))
        lines.append(f"## Event #{idx}: `{item.get('userPrincipalName')}` -> `{item.get('appDisplayName')}`")
        lines.append(f"- **Timestamp (UTC):** `{item.get('createdDateTime')}` | **Interactive:** `{item.get('isInteractive')}`")
        lines.append(f"- **Correlation ID:** `{item.get('correlationId')}`")
        lines.append(f"- **Error Code:** `AADSTS{item.get('errorCode')}` (`{item.get('errorCode')}`) - {item.get('failureReason')}")
        if item.get("additionalDetails"):
            lines.append(f"- **Additional Details:** {item.get('additionalDetails')}")
        lines.append(f"- **CA Status:** `{item.get('conditionalAccessStatus')}` | **Auth Requirement:** `{item.get('authenticationRequirement')}`")
        lines.append(f"- **Network & Client:** IP `{item.get('ipAddress')}` ({item.get('location')}) | Client: `{item.get('clientAppUsed')}`")
        lines.append(
            f"- **Device Context:** OS=`{dev.get('operatingSystem')}`, Browser=`{dev.get('browser')}`, "
            f"TrustType=`{dev.get('trustType')}`, Compliant=`{dev.get('isCompliant')}`, Managed=`{dev.get('isManaged')}`, "
            f"DeviceId Present=`{bool(dev.get('deviceId'))}`"
        )
        if item.get("riskLevelDuringSignIn") and str(item.get("riskLevelDuringSignIn")).lower() != "none":
            lines.append(f"- **Identity Protection Risk:** Level=`{item.get('riskLevelDuringSignIn')}`, Detail=`{item.get('riskDetail')}`, State=`{item.get('riskState')}`")

        failing_policies = _safe_list(item.get("failingConditionalAccessPolicies"))
        if failing_policies:
            lines.append("\n### Failing / Blocking Conditional Access Policies")
            lines.append("| Policy Name | Result | Enforced Grant Controls | Enforced Session Controls |")
            lines.append("| --- | --- | --- | --- |")
            for pol in failing_policies:
                pol_dict = _safe_dict(pol)
                grants = ", ".join(str(g) for g in _safe_list(pol_dict.get("enforcedGrantControls"))) or "None"
                sessions = ", ".join(str(s) for s in _safe_list(pol_dict.get("enforcedSessionControls"))) or "None"
                lines.append(f"| `{pol_dict.get('policyName')}` | `{pol_dict.get('result')}` | `{grants}` | `{sessions}` |")

        diagnostic_hints = _safe_list(item.get("diagnosticHints"))
        if diagnostic_hints:
            lines.append("\n### Automated Root-Cause Anomaly Detections")
            for hint in diagnostic_hints:
                hint_dict = _safe_dict(hint)
                lines.append(f"- **[{hint_dict.get('code')}] {hint_dict.get('title')}:** {hint_dict.get('description')}")

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
