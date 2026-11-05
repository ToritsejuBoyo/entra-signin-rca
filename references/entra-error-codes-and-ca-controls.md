# Entra ID Sign-In Error Codes (`AADSTS`), Conditional Access Controls & Trust Matrix Reference

Use this reference during `entra-signin-rca` execution to decode numeric Entra `status.errorCode` values, Conditional Access grant evaluation rules, and device/browser PRT anomalies.

---

## 1. High-Frequency Entra ID (`AADSTS`) Sign-In Error Codes

| Error Code (`status.errorCode`) | Symbolic Name | Meaning in Sign-In Logs | Typical Root Cause & Remediation |
| --- | --- | --- | --- |
| **0** | `Success` | Primary and secondary auth succeeded. | Check if `reportOnlyFailure` policies exist in `appliedConditionalAccessPolicies[]` when testing new CA policies. |
| **50053** | `IdsLocked` | Account is locked out due to repeated bad password attempts or Smart Lockout. | Inspect `ipAddress` and `clientAppUsed`. Often caused by a stale mobile mail client or cached credential in Windows Credential Manager hammering legacy/modern auth after a password reset. |
| **50055** | `InvalidPasswordExpiredPassword` | User's password is expired. | If Self-Service Password Reset (SSPR) is not enabled or user is on a non-interactive client, they cannot complete the inline password change flow. |
| **50058** | `UserInformationNotProvided` | Silent sign-in request (`prompt=none`) failed because user interaction is required. | Very common in non-interactive logs before an interactive MFA prompt. Only treat as a real problem if the client app fails to fall back to an interactive prompt. |
| **50072 / 50074** | `UserStrongAuthEnrollmentRequired` / `UserStrongAuthClientAuthNRequired` | MFA is required by a Conditional Access policy or risk policy, and user either needs to enroll (`50072`) or complete challenge (`50074`). | Check if a blocking CA policy prevents the user from accessing the MFA registration portal from an untrusted location. |
| **50076** | `UserStrongAuthClientAuthNRequired` | Due to a configuration change made by administrator, or because user moved to a new location, MFA is required. | Triggered when user switches IP/network (e.g., VPN drop or mobile hotspot) or a new CA MFA policy takes effect. |
| **50079** | `UserStrongAuthEnrollmentRequiredInterrupt` | User is required to register security info (MFA methods). | Verify user matches the Authentication Methods registration campaign and is not blocked from `mysignins.microsoft.com`. |
| **50097** | `DeviceAuthenticationRequired` | Device authentication (PRT) is required to access this resource. | Browser or client app failed to present a Primary Refresh Token. Check browser extension / Incognito mode. |
| **50126** | `InvalidUserNameOrPassword` | Invalid username or password (or on-prem AD Pass-Through Auth / PHS mismatch). | If user recently changed password on-prem, check Entra Connect Sync health for Password Hash Sync latency. |
| **50158** | `ExternalSecurityChallenge` | External security challenge (Duo / 3rd-party Custom Control or EAM) was not satisfied. | Verify External Authentication Method (EAM) provider connectivity or user enrollment in the third-party MFA tenant. |
| **53000** | `DeviceNotCompliant` | Conditional Access policy requires a compliant device, and the device is not compliant. | Either `deviceDetail.deviceId` is missing (browser lacks PRT passthrough) OR Intune marked the device non-compliant (`isCompliant: false`). |
| **53001** | `DeviceNotDomainJoined` | Conditional Access policy requires Hybrid Entra Join (`ServerAd`), and device is not joined. | Check `dsregcmd /status` on the Windows endpoint (`AzureAdJoined`, `DomainJoined`, `AzureAdPrt`). |
| **53003** | `BlockedByConditionalAccess` | Access has been blocked by Conditional Access policies. | Inspect `appliedConditionalAccessPolicies[]` for `enforcedGrantControls: ["Block"]` or an unsatisfied grant control where the client cannot remediate interactively. |
| **530032** | `BlockedBySecurityDefaults` | Access blocked by tenant Security Defaults. | Tenant has Security Defaults enabled (which blocks all Legacy Auth and enforces MFA). |
| **530034** | `DelegatedAdminBlocked` / `AuthStrengthNotMet` | Authentication Strength requirement (e.g., Phishing-Resistant MFA) was not satisfied. | Policy requires FIDO2 / WHfB / Certificate-Based Auth, but user only has SMS/Authenticator Push registered. |
| **70043** | `BadTokenDueToSignInFrequency` | The refresh token has expired or is invalid due to sign-in frequency conditional access checks. | Aggressive Session Control (`Sign-in frequency: Every time` or `1 hour`) breaking background token renewal in Outlook/Teams. |

---

## 2. Conditional Access Policy Evaluation Precedence Rules

1. **Explicit `Block` Wins:** If a user matches 5 Conditional Access policies—4 of which grant access with MFA and 1 of which has `Grant = Block`—the user is **Blocked** (`53003`).
2. **Multiple Policies = Logical `AND`:** If Policy A requires `MFA` and Policy B requires `CompliantDevice`, the user must satisfy **both** `MFA` AND `CompliantDevice` to sign in.
3. **Single Policy Multiple Controls = Operator Dependent (`AND` vs. `OR`):**
   - `"operator": "AND"` -> User must satisfy **every** checked box in that policy.
   - `"operator": "OR"` -> User only needs to satisfy **one** checked box (e.g., *Require MFA* **OR** *Require Hybrid Entra Joined device*).

---

## 3. Classic Browser & Device Trust Pitfalls (Why Compliant Laptops Fail `53000`/`53003`)

When a Conditional Access policy enforces **`Require device to be marked as compliant`** or **`Require Microsoft Entra hybrid joined device`**, Entra ID relies on the client presenting a cryptographically signed **Primary Refresh Token (PRT)** containing the `deviceId` claim.

| OS & Client Scenario | Symptom in Sign-In Log | Technical Cause & Fix |
| --- | --- | --- |
| **Windows 10/11 + Google Chrome (without extension or GPO)** | `deviceDetail.deviceId` is `""` (empty); `isCompliant` is `false`. | Enable Chrome `CloudAPAuthEnabled` registry policy (`HKLM\Software\Policies\Google\Chrome\CloudAPAuthEnabled = 1`) or install the **Windows Accounts** extension, or use Microsoft Edge. |
| **Windows 10/11 + Mozilla Firefox** | `deviceDetail.deviceId` is `""` (empty). | Enable `network.http.windows-sso.enabled = true` in Firefox enterprise policies (`policies.json` / Intune ADMX). |
| **Any Browser in Incognito / InPrivate Mode** | `deviceDetail.deviceId` is `""` (empty). | InPrivate/Incognito intentionally suppresses OS PRT transmission to protect privacy. Therefore, any CA policy requiring a compliant device will **always fail** in Incognito/InPrivate. |
| **macOS + Safari / Chrome / Edge** | `deviceDetail.deviceId` is `""` or unregistered. | Verify the **Intune Company Portal** app is installed, the user has completed **Register Device**, and the **Microsoft Enterprise SSO plug-in** (Platform SSO) profile is deployed via MDM. |
| **Dual-Stack IPv4/IPv6 Office Network** | `location` matches outside Trusted Named Location; `ipAddress` is IPv6 (`2a00:...` or `2603:...`). | Admin added the office's public IPv4 `/29` to Entra **Named Locations**, but ISP enabled IPv6. Entra sees the client's IPv6 address and evaluates `Location != Trusted`. Fix: Add the corporate IPv6 `/48` or `/64` prefix to the Named Location. |

---

## 4. Read-Only Endpoint & Graph Verification Commands

### A. On a Windows Endpoint (`CMD` / `PowerShell` as the affected user)
```powershell
# Inspect Entra Join state, DeviceId, and PRT (Primary Refresh Token) status
dsregcmd /status | Select-String -Pattern "AzureAdJoined|DomainJoined|DeviceId|AzureAdPrt|AzureAdPrtUpdateTime|TenantId"
```
- `AzureAdPrt : YES` -> Endpoint has a valid PRT; if browser still fails, it is a browser SSO passthrough issue.
- `AzureAdPrt : NO` -> Endpoint lacks PRT; user must lock/unlock screen (`Win + L`) or sign in with Windows Hello / domain credentials.

### B. Microsoft Graph PowerShell (Read-Only Policy Inspection)
```powershell
# Connect with read-only scopes and inspect all enabled Conditional Access policies
Connect-MgGraph -Scopes "Policy.Read.All", "AuditLog.Read.All"
Get-MgIdentityConditionalAccessPolicy -All | Where-Object { $_.State -ne "disabled" } |
    Select-Object Id, DisplayName, State, @{N='GrantControls';E={$_.GrantControls.BuiltInControls -join ','}}, @{N='Operator';E={$_.GrantControls.Operator}}
```
