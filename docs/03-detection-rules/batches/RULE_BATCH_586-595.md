# Carthago — R586–R595 HTTP request-signature batch

**SOURCE CANDIDATE — UNVERIFIED.** C# authored, xUnit authored, **0 tests executed**, **0 builds executed**, **source-only branch candidate**. The rule registry is updated together with the source and tests during feature-branch publication. No release acceptance claimed.

## Provenance and scope

- Based entirely on the existing 2,500-rule research workbook (SigmaHQ source URLs already recorded there); no new external research.
- Each new ID maps to one distinct workbook research candidate; no convergence or broad composite rule.
- These rules classify only a bounded plaintext HTTP request and never claim successful exploitation, data disclosure, or authentication.
- `TrafficRecord` HTTP fields are public/settable: serialized or synthetic records can mimic provenance. Verify live PacketHandler capture reachability before operational promotion.
- TLS-encrypted HTTP is outside these request signatures unless a verified trusted decrypting producer is added. No HTTP response code is assumed.
- Shared helper handles evidence hygiene and per-rule instance cooldown; predicates stay independent.

## Ten-rule matrix

| Rule | Workbook | Priority | Network observable | Known overlap risk | Source |
|---|---|---|---|---|---|
| R586 | R2094 | P1 | WordPress wp2shell plugin access request; request only | R087/R092 generic webshell or URI; source review pending | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2026/Exploits/CVE-2026-63030/web_exploit_cve_2026_63030_webshell_plugin_access.yml |
| R587 | R2135 | P1 | ScreenConnect SetupWizard path request; request only | existing web probe families; source review pending | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2024/Exploits/CVE-2024-1709/web_exploit_cve_2024_1709_screenconnect.yml |
| R588 | R2280 | P1 | SolarWinds SUPERNOVA handler request; request only | R087/R092 generic webshell or URI; source review pending | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2020/TA/SolarWinds-Supply-Chain/web_solarwinds_supernova_webshell.yml |
| R589 | R2286 | P1 | WebLogic keystore script request; request only | R087/R092 generic webshell or URI; source review pending | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2018/Exploits/CVE-2018-2894/web_cve_2018_2894_weblogic_exploit.yml |
| R590 | R2943 | P1 | Rejetto HFS search injection request; request only | R089 generic injection; source review pending | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2014/Exploits/CVE-2014-6287/web_cve_2014_6287_hfs_rce.yml |
| R591 | R2957 | P1 | ADSelfService suspicious endpoint request; request only | R414 appliance probe; source review pending | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2021/Exploits/CVE-2021-40539/web_cve_2021_40539_adselfservice.yml |
| R592 | R2983 | P1 | DEWMODE webshell-shaped query request; request only | R087/R092 generic webshell or URI; source review pending | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2021/TA/UNC2546/web_unc2546_dewmode_php_webshell.yml |
| R593 | R3009 | P1 | Apache Spark doAs backtick request; request only | R089 generic injection; source review pending | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2022/Exploits/CVE-2022-33891/web_cve_2022_33891_spark_shell_command_injection.yml |
| R594 | R3026 | P1 | Bitbucket archive exec-prefix request; request only | R089 generic injection; source review pending | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2022/Exploits/CVE-2022-36804/web_cve_2022_36804_atlassian_bitbucket_command_injection.yml |
| R595 | R3053 | P1 | Grafana plugin traversal request; request only | R086 generic traversal; source review pending | https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2021/Exploits/CVE-2021-43798/web_cve_2021_43798_grafana.yml |

## Authoring and scenario contracts

- Test file: `Carthago.Tests/R586R595AdvancedAccuracyBatchTests.cs`.
- Tests for every rule: genuine positive, benign near-miss, contradictory/missing evidence, wrong method/malformed URI, duplicate/out-of-order/cooldown, redacted event and source-only Shadow registry.
- No test/build/run commands executed (explicit owner restriction). No SHA-backed compilation evidence.
- Per-rule cooldown is ten minutes per exact IP peer pair. Maximum 1,024 live pairs per rule, fail closed at capacity.
- HTTP URI is never placed in structured event evidence, preventing raw potentially sensitive URL parameters from leaking through this rule.
- Static, exact URL signatures can be spoofed by authorized tests/scanners; remain Shadow until precision and provenance are validated.
- Each rule presently accepts a single matching request; capture fragmentation and evasive encodings are not implemented.

## Integration contract — DO NOT RUN TESTS

1. Recheck live `feature/carthago-reliability-hardening` HEAD and registration ending at R585.
2. Keep all rule sources in `Carthago/Engine/Rules/Expansion/`.
3. Retain `Carthago.Tests/R586R595AdvancedAccuracyBatchTests.cs`.
4. Register exactly R586–R595 after R585 in `RuleRegistry.CreateDefaultRules()`.
5. Retain this batch document and the source-only publication SHA in git history.
6. Keep work unverified and do not execute tests, builds or captures without explicit owner authorization.

## Unresolved GA gates

- Capture-path proof that `HttpMethod`/`HttpUri` actually derive from live packets (not record imports).
- Source-level non-overlap against each neighboring existing rule; specificity alone is not sufficient to prove independence.
- Compile, xUnit, replay, precision/false-positive assessment, and promotion authorization.
- Owner authorized direct feature-branch publication; preserve expected-HEAD protection and never force-push.
