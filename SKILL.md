---
name: entra-signin-rca
description: Analyze Microsoft Entra ID (Azure AD) Interactive and Non-Interactive Sign-In JSON/CSV logs to pinpoint why a user, service principal, or device failed authentication or was blocked by overlapping Conditional Access (CA) policies. Use when troubleshooting AADSTS error codes, MFA loops, compliant-device lockouts, legacy authentication blocks, or Conditional Access policy conflicts.
---

# Entra ID Conditional Access & Sign-In Root Cause Analyzer (`entra-signin-rca`)

## Purpose & Target Roles
Built for **Microsoft 365 Administrators, Identity & Access Management (IAM) Engineers, Systems Administrators, and MSP Escalation Engineers**. Overlapping Conditional Access policies, hybrid Entra Join delays, and Continuous Access Evaluation (CAE) token revocations produce dense JSON logs that are tedious to inspect manually in the Entra portal. This skill parses exported sign-in records, identifies the exact blocking condition or unsatisfied grant control, and designs a safe remediation that never weakens tenant-wide security posture.

## Operating Rules & Safety Guardrails
1. **Never Recommend Disabling Security Defaults or Broad MFA Policies:** Never advise turning off a Conditional Access policy globally or adding permanent user exclusions to bypass a block without a compensating control or time-bound Change Request.
2. **Preserve Break-Glass Hygiene:** Whenever suggesting a Conditional Access policy modification, explicitly remind the administrator to verify that at least two cloud-only Emergency Access (Break-Glass) accounts (`*.onmicrosoft.com`) are excluded from the policy and tested in **Report-only** mode first.
3. **Distinguish Interactive vs. Non-Interactive vs. Service Principal Sign-Ins:** Background token refreshes (`isInteractive: false`) often fail silently on legacy protocols or device compliance drift before the user sees a prompt. Always examine both.
4. **Sanitization & Proof-of-Work:** Support `-s / --sanitize` via the bundled Python parser and `--generate-proof-of-work` output mode so engineers can share anonymized sign-in RCAs without leaking tenant IDs (`tenantId`), user object IDs, or public IP addresses.

---

## Step 1: Telemetry & Input Acquisition

Accept any of the following inputs from the user:
1. **Direct Microsoft Graph PowerShell One-Liner (Fastest & Zero Disk Footprint):**
   Instruct the administrator to query the affected user's most recent failed sign-in and pipe directly to the parser:
   ```powershell
   Connect-MgGraph -Scopes "AuditLog.Read.All" -NoWelcome
   Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'user@example.com' and status/errorCode ne 0" -Top 1 |
       ConvertTo-Json -Depth 6 |
       python scripts/parse-entra-signin.py -i - --sanitize --format markdown
   ```
2. **Exported Entra Sign-In JSON (`SignIns_*.json`):**
   Downloaded from **Microsoft Entra Admin Center -> Identity -> Monitoring & health -> Sign-in logs -> Download -> Download JSON**.
   Run the zero-dependency Python parser locally:
   ```bash
   python scripts/parse-entra-signin.py --input SignIns_export.json --sanitize --format markdown
   ```
3. **Pasted Troubleshooting Details / Error Screen Text:**
   If the user only has the end-user error screen (`Request Id`, `Correlation Id`, `Timestamp`, `Error Code: 53003`, `AADSTS50076`, etc.), use `references/entra-error-codes-and-ca-controls.md` to guide targeted inspection.

---

## Step 2: Multi-Step Diagnostic & RCA Workflow

Execute these 5 analytical phases in order:

### Phase 1: Authentication Status & Error Code Triage (`status.errorCode`)
1. Inspect `status.errorCode`, `status.failureReason`, and `status.additionalDetails`.
2. Look up the numeric code in `references/entra-error-codes-and-ca-controls.md` (e.g., `0` = Success, `50058` = Silent sign-in failure, `50074`/`50076` = MFA required by CA or risk change, `50158` = External security challenge not satisfied, `53000` = Device not compliant, `53003` = Blocked by Conditional Access, `530032` = Blocked by Security Defaults, `70043` = Refresh token expired due to sign-in frequency).
3. Determine whether the failure occurred at **Primary Authentication** (bad password, account locked `50053`, federated IdP error) or **Post-Authentication Conditional Access Evaluation**.

### Phase 2: Conditional Access Policy Evaluation Matrix
Iterate through every entry in `appliedConditionalAccessPolicies[]`:
1. Filter for policies where `result` is `"failure"` or `"reportOnlyFailure"`.
2. For each failing policy, inspect:
   - `displayName` and `id`
   - `enforcedGrantControls[]` (e.g., `Block`, `Mfa`, `CompliantDevice`, `DomainJoinedDevice`, `ApprovedApplication`, `CompliantApplication`, `PasswordChange`)
   - `enforcedSessionControls[]` (e.g., `SignInFrequency`, `ConditionalAccessAppEnforcedRestrictions`, `PersistentBrowserSessionMode`)
   - `conditionsNotSatisfied` and `conditionsSatisfied` bitmasks/strings.
3. **Multiple Policy Intersection Rule:** Remember that in Entra ID:
   - An explicit `Block` in **any** matching policy overrides all `Grant` policies.
   - Across multiple matching `Grant` policies, **ALL** policies must be satisfied (`AND` logic across policies), whereas within a single policy, `grantControls.operator` defines whether controls are `AND` ("Require all the selected controls") or `OR` ("Require one of the selected controls").

### Phase 3: Device, Client App & Network Context Correlation
Explain *why* the condition matched or the grant control failed by inspecting:
- **Device State (`deviceDetail`):** Check `isCompliant`, `isManaged`, `trustType` (`AzureAd`, `ServerAd` / Hybrid Entra Joined, `Workplace` / Entra Registered), `operatingSystem`, and `browser`.
  - *Classic Pitfall:* User uses Chrome/Firefox without the Windows Accounts / Single Sign-On extension or macOS without Company Portal SSO extension -> `deviceDetail.deviceId` is blank (`""`), so Entra treats the device as **Unregistered/Non-Compliant** and triggers `53000`/`53003` even though the laptop itself is Intune-compliant.
- **Client App (`clientAppUsed` & `appDisplayName`):** Check if `clientAppUsed` is `Browser`, `Mobile Apps and Desktop clients`, or a legacy protocol (`Exchange ActiveSync`, `IMAP4`, `POP3`, `SMTP`, `Other clients`).
- **Location & Network (`location`, `ipAddress`, `networkLocationDetails`):** Check if IPv6 fallback caused the client to appear outside an IPv4-only Named Location (`Trusted Corporate Office IP`), triggering an unexpected location block.
- **Authentication Strength & MFA (`authenticationRequirement`, `authenticationDetails`, `authenticationStrength`):** Check if the policy required **Phishing-Resistant MFA** (FIDO2 / Windows Hello for Business / Passkey) while the user only registered Microsoft Authenticator Push (`530034` / Authentication Strength mismatch).

### Phase 4: Least-Privilege Remediation Design
Formulate two remediation paths:
1. **Immediate User/Endpoint Fix (Zero Policy Change):** e.g., Sign into Microsoft Edge profile, trigger Intune compliance sync (`Company Portal -> Check Status`), register a FIDO2 passkey, or add the client's IPv6 `/48` prefix to the Trusted Named Location.
2. **Policy Architecture Fix (If Policy is Misconfigured):** Provide exact condition/grant adjustments (e.g., switching Grant operator from `AND` to `OR` between `Require multifactor authentication` and `Require device to be marked as compliant`, or scoping a legacy block exclusion strictly to a specific Named Location + Service Account). Always include a Microsoft Graph PowerShell verification snippet.

---

## Step 3: Structured Deliverable Generation
Format the final output strictly using `assets/ca-lockout-rca-report-template.md`. Include:
- Sign-In Event Header & Identity Context
- Conditional Access Policy Evaluation Table
- Exact Technical Root Cause Explanation
- Remediation Options (Endpoint Fix vs. Policy Change + Rollback Plan)

---

## Step 4: Portfolio / Proof-of-Work Mode (`--generate-proof-of-work`)
When `--generate-proof-of-work` is requested:
1. Redact all real `userPrincipalName`, `userId`, `tenantId`, `ipAddress`, and internal policy GUIDs.
2. Generate a **"Verified IAM Case Study"** demonstrating how the engineer resolved a complex Conditional Access lockout using structured JSON telemetry analysis without compromising Zero Trust controls.

## Bundled Resources Reference
- **Parser Script:** `scripts/parse-entra-signin.py` (Zero-dependency Python 3 parser for Entra Sign-In JSON exports with `--sanitize` and `--format markdown|json`).
- **Technical Reference:** `references/entra-error-codes-and-ca-controls.md` (Lookup reference for `AADSTS` error codes, CA grant/session controls, and browser/device trust pitfalls).
- **Output Template:** `assets/ca-lockout-rca-report-template.md` (Standard IAM RCA & CAB-ready remediation template).
