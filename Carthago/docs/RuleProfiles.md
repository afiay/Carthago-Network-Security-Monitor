# Rule Profiles

Carthago supports profile-aware defaults while preserving explicit rule overrides.

Profiles:

- `HomeLab`
- `SmallBusiness`
- `Enterprise`
- `IoTHeavy`
- `OTSegment`
- `Research`

Rule modes:

```text
Disabled -> not evaluated; skipped is recorded.
Shadow   -> evaluated and journaled, hidden from default alert flow.
Alert    -> evaluated, journaled, and returned to downstream alert/correlation paths.
```

Explicit per-rule config overrides profile defaults.

Example:

```json
{
  "Version": 3,
  "Profile": "SmallBusiness",
  "Rules": {
    "R094": { "Enabled": true, "Mode": "Shadow", "Threshold": 10 },
    "R084": { "Enabled": true, "Mode": "Alert" }
  }
}
```

Rule profile changes must never reset the detection journal, baseline, feedback, or UI preferences.
