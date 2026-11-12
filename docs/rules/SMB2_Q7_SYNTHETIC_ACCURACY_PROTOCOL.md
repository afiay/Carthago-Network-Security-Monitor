# Q7-v1 — SMB2 synthetic paired accuracy protocol

## Scope and provenance

Six Candidate/Shadow rules R903/R908/R910/R919/R942/R950. 24 scenario-rule pairs, four labels per rule. Separately authored binary IPv4/TCP SMB2 WRITE fixture through PacketHandler, not the Q4–Q6 fixture helper. Process attribution and R950 HTTP observation are synthetic typed inputs. All addresses, payloads, identity and scenario labels are laboratory constructs. No actual remote connections, malicious binaries, credentials, independent PCAPs or production labels. This is a *synthetic diagnostic baseline*, not an independent holdout or field-performance estimate. Do not revise this matrix to conceal known gaps; new versions must preserve original labels and report changes.

| Rule | Malicious intent (synthetic) | Benign lookalike (same observable shape) | Benign control |
|---|---|---|---|
| R903 | Unauthorized remote management staging | Approved PowerShell deployment and WinRM | WinRM over a different port |
| R908 | Unauthorized external file-write attempt | Approved partner SMB file transfer | Different client source port |
| R910 | Directory discovery then unauthorized file staging | Approved inventory/deployment | LDAP to another host |
| R919 | Unauthorized remote service staging | Approved PsExec maintenance | RPC port mismatch |
| R942 | Unauthorized pivot toward industrial device | Authorized engineering workstation maintenance | Modbus contact from another host |
| R950 | Unauthorized script staging | Approved script deployment | HTTP retrieval of non-script name |

For each rule, the fourth scenario is a malicious-intent copy with one missing captured WRITE byte, thus a producer-limited opportunity; retain separately rather than classify as a supported detector false negative. Intent labels deliberately differ between identical observable shapes. That is a counterexample to claiming authorization or maliciousness from traffic alone, not a flaw in the fixture.

## Measurement and expected baseline (not measured yet)

Run the test with detailed console output. The aggregate test emits per-scenario raw match, effective policy mode, confidence, producer availability, and confusion matrices using DetectionQualityMetrics. Count a scenario once for its target rule, not all 965 rules. Evaluate the runtime precision gate with configured Alert and Research profile; do not claim the gate call is an end-to-end runtime deployment benchmark.

Expected from current predicates: raw TP=6 FP=6 FN=0 TN=6, precision 50%, recall 100%, specificity 50%; effective alerts TP=0 FP=0 FN=6 TN=12, precision undefined (no alerts), recall 0% because all candidates remain Shadow. Six producer gaps excluded from supported metrics. A passing test documents these expected limitations, not a quality threshold. Ratios are deliberately constructed, tiny, correlated and not representative of deployment prevalence. No measured latency or independent validation claimed.

## Next gates

Collect separately controlled benign and unauthorized lab traces with independent authorization/asset/change-window ground truth, packet capture provenance, and per-scenario expected target operation. Include encrypted SMB3, segmentation/reassembly, ordinary file copies, failed attempts, signed SMB, legitimate administration and matched unauthorized lookalikes. Freeze the corpus before tuning, keep holdout separate from development, report supported coverage and producer gaps, then measure per-rule raw matches and effective alerts with uncertainty. Do not promote based on this diagnostic matrix. Existing Q6 share/category metadata cannot prove unauthorized intent. No thresholds or rule IDs changed.

Run:
`dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --no-build --no-restore --filter "FullyQualifiedName~Smb2PairedAccuracyQualificationTests" --logger "console;verbosity=detailed"`
