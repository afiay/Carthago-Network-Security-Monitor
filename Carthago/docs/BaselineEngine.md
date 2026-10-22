# Baseline Engine

The baseline store is persisted outside UI preferences under:

```text
%ProgramData%\Carthago\baseline\baseline.json
```

It records:

- host identities
- MAC/IP observations
- known host destinations
- known ASNs/countries
- DNS domains
- service observations
- cloud/SaaS observations

Baseline decisions include:

- first seen
- known
- learning mode
- observation count
- first seen / last seen timestamps

Baseline-backed rules include:

```text
R057, R058, R059, R060, R062, R064, R065, R066, R095, R103, R104
```

The first observation is recorded. Learning/shadow behavior must remain traceable and must never erase detections.
