# Active sensor dashboard KPI provenance — 2026-11-16

The **Active Sensors** overview KPI is not a global count of installed detectors or configured rules.

- When the GUI session scheduler holds its machine-wide reservation, the KPI shows the number of its approved, non-blocked scheduled profiles. An idle interval between probes still counts as scheduled. Blocked profiles are shown separately. The count does not include a separate service or foreground monitor process.
- When the GUI does not hold the reservation, the KPI displays **—** and a live count marked unverified. The caption reports the number of saved configurations read from the local active-sensor profile store. Saved profiles are not an execution grant, heartbeat, or proof of runtime activity.
- Storage failure displays **inventory unavailable**, not zero.
- Closing the GUI active sensor manager stops its session scheduler. Scheduled active probes require explicit authorization; passive Npcap capture does not start them.

## Verification

Run the projection tests on Windows:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~ActiveSensorKpiProjectionTests"
```

For an owner-authorized runtime check, stop passive capture, select a LAN host, open **Active sensor manager (session)**, approve and start a profile, and verify the card displays the GUI's live scheduled count and any blocked profiles. Stop/close the manager and verify the card returns to **—** with a saved-profile caption, never inventing an external runtime count.

A unified machine-wide count requires an additional trustworthy cross-process status contract from the foreground/service workers. That has **not** been implemented or qualified by this dashboard-only change.
