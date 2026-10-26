# Replay evidence coverage

Carthago's offline benchmark distinguishes labeled detector tests from alert-policy decisions. These are different measurements.

## Inspect controls

Run local verification from PowerShell, then inspect individual rule evidence:

```powershell
.\verify-local.ps1 -Details -LiveOutput
.\scripts\inspect-rule-evidence.ps1
.\scripts\inspect-rule-evidence.ps1 -MissingPaired -Top 25
```

The per-rule report counts each explicitly labeled fixture once for each named rule. A rule is considered paired only when there is at least one labeled match from a malicious scenario and at least one explicitly asserted nonmatch from a separate scenario. Unlabeled traffic is never silently counted as a rule-specific negative control. These counts are not estimates of production precision or recall.

## New paired examples

| Rule | Positive replay | New negative replay | Boundary checked |
| --- | --- | --- | --- |
| R275 | oauth-device-code-phishing | r275-routine-device-code-initiation | An OAuth device-code-related request without an observed user-code pairing must not be called phishing |
| R343 | ad-psremoting-encoded-command | r343-powershell-remoting-without-encoded-payload | Normal WinRM PowerShell remoting without an encoded command must not match the encoded-remoting rule |
| R485 | bacnet-write-property | r485-bacnet-readproperty-no-write | BACnet ReadProperty traffic must not be confused with a WriteProperty operation |

These are synthetic controls. One paired control per rule is a starting point, not sufficient coverage of legitimate variations, evasions, parser errors or production traffic. New candidate alerts remain subject to the existing independent confidence, baseline and environment policy gates.
