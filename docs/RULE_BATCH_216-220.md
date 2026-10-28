# R216–R220 — Cloud listing and collaboration-channel request precision

**CANDIDATE / UNVERIFIED — 81 advanced xUnit facts authored, ZERO executed.**

| Rule | Candidate production change | Authored facts |
| --- | --- | ---: |
| R216 | Exact GCS JSON bucket-object list path or XML bucket-prefix request; reject object/media GET; typed HTTP, authority and replay checks. | 15 |
| R217 | Exact Slack webhook token segments or files.upload POST; require multipart or large declared Content-Length, suppress Slack desktop process, redact token-bearing paths. | 16 |
| R218 | Exact Discord webhook or versioned channel attachment POST, typed multipart/declared upload context, suppress ordinary Discord client, redact webhook token. | 16 |
| R219 | Exact Telegram Bot API sendDocument POST with bot token shape and upload context, reject sendMessage and Info-only claims, redact bot token. | 16 |
| R220 | Exact paste/drop host and parsed upload verb, bounded per-instance/per-source/provider request windows, packet-ID dedup, out-of-order and browser thresholds; distinguish declared body length from delivery. | 18 |
| **Total** | **Five consecutive rules** | **81** |

**Production paths:** `Carthago/Engine/Rules/Expansion/R216_GoogleStorageBucketEnumerationRule.cs` through `R220_PasteServiceHighVolumePostRule.cs`, new `NetworkBatch216220Evidence.cs`, and scoped host/path redaction in `HttpApiPrecisionDetectionRuleBase.cs`. Existing `NetworkBatch156165ReplayGuard` and `NetworkBatch201205Window` are reused; no global state or new configuration keys. Rule profiles, confidence floors, thresholds, default modes, approval and baseline gates are unchanged.

**Test paths:** `Carthago.Tests/R216AdvancedAccuracyBatchTests.cs` through `R220AdvancedAccuracyBatchTests.cs` and `NetworkBatch216220Context.cs`. Per-rule scenarios include typed positive, unrelated provider, packet Info spoof, contradictory Host, UDP/HTTP conflict, absent method, duplicate ID, out-of-order event, source isolation, token/query redaction, unchanged confidence/mode and domain-specific benign controls. R220 additionally covers five-post threshold, duplicate resistance, source separation, expired window and browser six-post requirement. All 81 facts are **authored, NOT executed**. No development replay labels were created because packet request metadata does not establish actual exfiltration.

**Candidate commits:** source `9dd80a0b4f5901f1ab1c3f8de75298bae512a473`; tests `f7d662bad5ba50182060740703b2234c77b00b2d`; static fixture/window correction `105501ecb04d13ca86c2c3f5fe5f0ba226d9c2d0`. The test commit message contains an outdated count; the file-level [Fact] count is 81, as recorded here.

## Observable evidence and limitations

`PacketHandler` parses cleartext HTTP request metadata but does not decrypt HTTPS. HTTPS-only Slack, Discord, Telegram and GCS traffic therefore cannot be assumed reachable through current packet capture; synthetic typed HTTP fixtures validate contracts only, not live field recall. `Content-Length` is a **declared request-body length**, not proof bytes were sent or accepted. Multipart is an observed request header, not body verification. R217–R220 detect request patterns, not successful exfiltration, uploaded content or authorization failure. R220 counts distinct parsed posting requests, not transmitted file bytes. Approved collaboration bots and sanctioned file-transfer workflows remain plausible benign equivalents; attribution and allowlist integration require separate runtime review. The R216 JSON/XML path restriction may reduce recall for alternative API routes.

No dotnet build, xUnit, replay, benchmark, frozen V1/V2 holdout, CI, GitHub Actions or Windows runner was executed. The single deferred verifier `scripts/verify-all-rule-batches.ps1` is unchanged. Frozen R102 V1 **FAILED 4/6**, immutable; V2 awaits independent licensed PCAP and analyst review. R102 80%, R118 86%, R163 84% floors, all other thresholds, default Shadow/Disabled/Alert policy, asset approvals, baseline readiness and evidence privacy remain unchanged.

**Next R221–R225, followed by R226–R230.**
