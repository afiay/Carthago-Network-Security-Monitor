# Carthago v12 Incident Host VM build fix

This pass restores the missing `IncidentHostVm` view model used by the incidents workspace.

## Fixed

- Added `IncidentHostVm` with host, role, risk score, incident count, and display-label properties.
- Preserved full host values through tooltip support.
- Prevented affected-host values from wrapping vertically in the incident details panel.
- No production demo data, secrets, `bin/`, or `obj/` files were added.

## Local validation

Run:

```powershell
dotnet restore .\Carthago.sln
dotnet build .\Carthago.sln
dotnet run --project .\Carthago.csproj
```
