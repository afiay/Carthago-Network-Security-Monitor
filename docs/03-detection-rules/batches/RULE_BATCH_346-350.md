# R346–R350 — MSSQL and LDAP operation provenance

**CANDIDATE — UNVERIFIED.** Five consecutive rules, **70 advanced xUnit cases authored (14 per rule), ZERO executed**. Static source inspection only. PacketHandler does not expose trusted authenticated TDS/SQL procedure results, LDAP BER search/bind outcomes or SAMR policy-read results. No positive attack events invented.

**R346 (14 unexecuted cases):** `MSSQL_COMMAND_AUDIT_UNAVAILABLE`. xp_cmdshell needs authenticated SQL procedure invocation and server-side outcome; a string or TDS port is not execution.

**R347 (14 unexecuted cases):** `MSSQL_LINKED_SERVER_AUDIT_UNAVAILABLE`. Linked-server enumeration needs parsed authenticated query and server result, not OPENQUERY text.

**R348 (14 unexecuted cases):** `LDAP_ADMINSDHOLDER_AUDIT_UNAVAILABLE`. AdminSDHolder reconnaissance needs parsed LDAP search/base/attributes, authenticated principal and approved directory context.

**R349 (14 unexecuted cases):** `LDAP_SPN_SEARCH_AUDIT_UNAVAILABLE`. SPN enumeration needs parsed authenticated LDAP search; Kerberoasting additionally requires corroborating KDC ticket context.

**R350 (14 unexecuted cases):** `LDAP_PASSWORD_POLICY_AUDIT_UNAVAILABLE`. Password-policy read needs parsed authenticated LDAP/SAMR operation and outcome; attribute names do not establish reconnaissance.

Source: `Carthago/Engine/Rules/Expansion/R346_MSSQLXpCmdshellUseIndicatorRule.cs`, `Carthago/Engine/Rules/Expansion/R347_MSSQLLinkedServerEnumerationRule.cs`, `Carthago/Engine/Rules/Expansion/R348_LDAPAdminSDHolderReconRule.cs`, `Carthago/Engine/Rules/Expansion/R349_LDAPKerberoastSPNEnumerationRule.cs`, `Carthago/Engine/Rules/Expansion/R350_LDAPPasswordPolicyReconRule.cs`. Tests: `Carthago.Tests/R346AdvancedAccuracyBatchTests.cs` through `R350AdvancedAccuracyBatchTests.cs`, using existing `NetworkBatch321325Context`.

Each rule has six behavior-specific negative theory cases plus eight invariants: spoofed Info, duplicate ID, out-of-order observations, independent sources, missing source, contradictory typed transport, secret-bearing metadata non-emission, original confidence/threshold/Alert profile. **All authored, NONE executed.** No positive identity/SQL/LDAP operation or field accuracy claimed. LDAP over TLS is not decrypted; no full TCP reassembly. SQL port 1433/1434 and LDAP 389/636 are not proof of authenticated operation. R343 legacy synthetic replay conflict from preceding batch remains open; no frozen or labeled replay changes.

No builds, dotnet, xUnit, replay, benchmark, frozen holdout, CI, GitHub Actions or runner. Deferred verifier `scripts/verify-all-rule-batches.ps1` unchanged, PowerShell 5.1-safe. Floors, thresholds, modes, approvals, baseline readiness, privacy, approved architecture and frozen evidence preserved. R102 frozen V1 FAILED 4/6 immutable; V2 pending independent licensed PCAP and analyst approval.

**R341–R350 total 140 authored unexecuted advanced cases. Next R351–R355 then R356–R360.**
