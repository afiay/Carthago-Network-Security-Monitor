# CARTHAGO — R596–R605 independent HTTP request-signature candidates

**SOURCE CANDIDATE — UNVERIFIED; 0 tests executed, 0 builds executed, source-only branch candidate.**

## Identity and scope

- Feature branch: `feature/carthago-reliability-hardening` only. The previous registry ended at R585; this batch is registered only through the expected-HEAD publication process.
- This batch follows R586–R595 and preserves the consecutive IDs R596–R605.
- All ten candidates are derived from the existing 2,500-rule workbook and carry the original workbook ID and SigmaHQ URL below. No fresh web research.
- Producer: `TrafficRecord` parsed cleartext HTTP request fields (`HttpMethod`, `HttpUri`, `HttpUserAgent`, `HttpRequestHeaders` when needed). These fields can also be set by import/fixtures, so live provenance remains a blocking promotion gate.
- Every predicate is independent, with its own C# class, rule identity, xUnit cases and instance-owned cooldown. A shared helper only validates input and bounds state; no convergence.
- None establishes HTTP status, exploitation, file disclosure, compromise or server-side effects. No TLS decryption assumed.

## Ten-rule matrix

| Rule | Workbook ID | Rank / priority | Exact observed request class | Nearest possible existing overlap | Research source |
|---|---|---|---|---|---|
| R596 | R3000 | 1253 / P1 | SonicWall Jarrewrite Suspicious User Agent Request | R416: broader SonicWall exposure rule; no matching jarrewrite/user-agent conjunction | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2021/Exploits/VisualDoor-Exploit/web_sonicwall_jarrewrite_exploit.yml |
| R597 | R3033 | 1263 / P1 | MODx tvs.php class_key traversal request | R086: generic path traversal; MODx-specific class_key + win.ini + NUL predicate | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2010/Exploits/CVE-2010-5278/web_cve_2010_5278_exploitation_attempt.yml |
| R598 | R2974 | 1246 / P1 | Windows local filesystem path in HTTP query | R008/R086: generic exfiltration or traversal; explicit Windows absolute-path query without traversal required | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/web/webserver_generic/web_susp_windows_path_uri.yml |
| R599 | R2274 | 1654 / P1 | Arcadyan apply_abstract.cgi encoded traversal request | R086/R128: general traversal/appliance; distinct encoded traversal on Arcadyan config endpoint | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2021/Exploits/CVE-2021-20090/web_cve_2021_20090_2021_20091_arcadyan_router_exploit.yml |
| R600 | R2938 | 1806 / P1 | Exchange HAFNIUM themes-resource POST request | R087/R319: broad webshell/OWA scan; POST+specific resources path differentiates | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2021/TA/HAFNIUM/web_exchange_exploitation_hafnium.yml |
| R601 | R2993 | 1826 / P1 | ReGeorg-like headerless control query POST | R087/R090: broad webshell/reverse-shell patterns; specific control parameters and absent headers | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/web/webserver_generic/web_webshell_regeorg.yml |
| R602 | R3034 | 1846 / P1 | SolarWinds Orion resource API bypass-shaped request | R422/R357: generic management/DevOps probes; distinct Orion resource-handler bypass shape | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2020/Exploits/CVE-2020-10148/web_cve_2020_10148_solarwinds_exploit.yml |
| R603 | R3037 | 1847 / P1 | WebLogic JNDI binding handle LDAP URI request | R084/R089: generic JNDI/injection; three conjunctive WebLogic-specific markers | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2021/Exploits/CVE-2021-2109/web_cve_2021_2109_weblogic_rce_exploit.yml |
| R604 | R3038 | 1848 / P1 | Exchange ECP or OWA VIEWSTATE-bearing GET | R088/R319: generic deserialization/Exchange admin; exact URL VIEWSTATE conjunction | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2020/Exploits/CVE-2020-0688/web_cve_2020_0688_msexchange.yml |
| R605 | R3041 | 1850 / P1 | Confluence upload.action filename traversal POST | R086/R177: generic traversal and risky upload extensions; Confluence upload.action/filename conjunction | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2019/Exploits/CVE-2019-3398/web_cve_2019_3398_confluence.yml |

## Distinction and limitations

- Specific URL signatures are more selective than general webshell, injection, Exchange appliance and traversals; **specificity alone does not prove there is no duplicate**. These candidates remain Shadow until source-level comparative verification.
- Workbook original web-server selections sometimes reference a response status that the packet model does not supply. Only candidates with a directly inspectable request-side branch were selected; they are **not exact reimplementations of every original Sigma rule**.
- For R601, a missing header summary is rejected rather than presumed to mean no Referer. Empty User-Agent is required; partial capture may cause false negatives.
- All rules require a coherent bounded HTTP record; they do not read free-form `Info`, parse untrusted JSON flags as trusted capture, or persist URI/query content into event evidence.
- Parser coverage for methods/URI/headers, capture reachability, real benign negatives, replay, recall and false-positive measurement are **unverified**.

## Test scenarios authored (not run)

- `Carthago.Tests/R596R605AdvancedAccuracyBatchTests.cs` has ten positive/negative inline datasets covering each rule independently.
- Other theory scenarios exercise each rule: wrong method, missing parser evidence, protocol contradictions, duplicate packet ID, out-of-order timestamp, ten-minute cooldown, malformed URI, oversized URI, redacted evidence, and Shadow registry uniqueness.
- R601 and R602 also have targeted header/profiler exclusion negatives.
- The fixture uses record-level structured HTTP fields. It **does not establish producer authenticity**; real PacketHandler capture scenarios are required for promotion.
- No tests, builds, CI, runner, replay or holdout processes were executed.

## Integration and outstanding GAs

1. R586–R595 and R596–R605 are separate consecutive batches on the existing feature branch; reuse the shared evidence-hygiene helper only.
2. Register R596–R605 after R595 in `RuleRegistry.CreateDefaultRules()`.
3. Retain this document with actual source and test statuses; commit SHA is available in git history.
4. Recheck remote HEAD and neighboring existing rule predicates before publishing; honor expected-HEAD protection. No force push.
5. Do not execute tests without explicit owner authorization. Keep candidate Shadow, and preserve frozen holdouts.

## Source references

- [Carthago rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md)
- [Rule registry](../Carthago/Engine/Rules/Catalog/RuleRegistry.cs)
- Original 2,500 candidate workbook and each URL recorded above (no fresh lookup).

