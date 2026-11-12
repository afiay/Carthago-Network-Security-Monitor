# Q8-v1 — Scoped SMB2 maintenance annotation

Q7 measured at e64e2df: 25/25 diagnostic tests, 12,318/12,318 full regression. Raw TP6 FP6 FN0 TN6; effective alerts TP0 FP0 FN6 TN12; six producer gaps. Both malicious and benign identical-shape matches scored 0.90. Q7-v1 unchanged.

## Scope

Opt-in local configuration, not authentication or proof of change execution. Only R910 and R950 end on a qualified SMB2 WRITE with same source/destination/process correlation and Q6 share/open context. R903/R919/R942 finish on a different protocol; R908 is public ingress. No approval applied to these four. Do not treat a process name, host inventory, suffix, IP or time match as verified authorization. A compromised approved workstation can still match the scope.

Configure `approved.smb2MaintenanceScopes` in environment-tuning.json, alongside explicit `approved.adminHosts`. Empty by default; example file contains no active entries. One entry requires changeId (1–64 ASCII alphanumeric, dash, underscore), exact ruleId (R910/R950), canonical RFC1918 IPv4 source/destination, processName (powershell.exe/pwsh.exe), shareKind (administrative-disk/other-disk), fileKind (executable/script/other), startsUtc/endsUtc (UTC ISO timestamps, max 8h, >45s). Scope IDs unique; overlapping matching entries fail closed. At most 256 entries; immutable snapshot of validated entries. ChangeId is an operator reference, not a verified ticket.

Observed terminal WRITE must be capture-attested, have Q6 CREATE correlation and exact categories, positive PID, local source/nonlocal destination, TCP socket-table attribution, matching event packet/endpoint/process and 45s window. Entire possible rule window must fit configured interval; expiration exclusive. Source must also be configured admin host. No hostname/CIDR/wildcard matching. No payload credentials or raw filenames retained.

ApprovedAssetRegistry returns Shadow disposition and explicit reason (configured scope matched; authorization not verified); existing RuleTuningCatalog records ApprovedAssetMatched and reason. Raw match, confidence, severity, evidence and Candidate/Shadow precision profile unchanged. Unmatched records remain existing mode, not automatically malicious. No alerts promoted, no raw detections deleted, no global whitelist.

## Verification

22 tests: two positive real rule-event to tuning checks, nineteen negative scope/record mismatch cases, one registry snapshot/rule isolation case. Synthetic process attribution in tests; capture-derived Q6 fixture used for WRITE. This tests configuration behavior, not independent malicious/benign discrimination. Q7 metrics unchanged; no precision improvement claim until independently labeled capture and authorization ground truth. Windows execution pending.

Next: independently capture lab workflows and obtain trusted execution/change records; cover compromised approved host, expired approvals, incorrect process identity and non-observable producers before considering deployment promotion.
