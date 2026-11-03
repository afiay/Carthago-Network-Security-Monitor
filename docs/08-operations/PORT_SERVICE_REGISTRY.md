# Port service registry update behavior

**SOURCE CANDIDATE — UNVERIFIED. TESTS AUTHORED — 0 EXECUTED.**

Carthago resolves TCP/UDP/SCTP/DCCP service names from the IANA service-name and
port-number registry.

## Normal operation

Normal application startup and normal port lookups are local-only.

1. If a valid per-user snapshot/cache already exists, Carthago may load it.
2. Otherwise Carthago loads the bundled `service-names-port-numbers.csv` shipped
   beside the application.
3. If neither source is available, the existing hardcoded/heuristic fallbacks
   remain available.

A packet lookup does **not** schedule a background HTTP request and does not
download or replace the CSV.

The bundled CSV is read from:

```text
<AppContext.BaseDirectory>\service-names-port-numbers.csv
```

Mutable port-registry state is stored under the current user's profile instead of
next to the executable:

```text
%LOCALAPPDATA%\Carthago\Data\IANA\
```

This avoids requiring write access to an installed application directory such as
`Program Files` and separates immutable shipped data from mutable user data.

## Explicit IANA update

Remote refresh is now opt-in at the code boundary through:

```csharp
await PortServiceResolver.UpdateIanaDatabaseAsync(cancellationToken);
```

That method performs the HTTPS request to the canonical IANA CSV endpoint and
writes the downloaded CSV to the per-user LocalAppData cache. A successful
download is written through a temporary file before replacing the cached CSV.

Normal `InitializeAsync`, `TryGetServiceInfo`, reverse lookups, inference and
packet analysis do not invoke the remote updater.

## Endpoint

The explicit updater uses the canonical IANA registry:

```text
https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
```

## Security and antivirus behavior

The previous implementation could combine network-monitor behavior, an automatic
background HTTPS request and writes under the application directory. The revised
design removes that automatic network/write path from ordinary packet processing.
Antivirus products may still inspect the executable and bundled CSV, but routine
service-name resolution is now a deterministic local read rather than a hidden
download/update operation.
