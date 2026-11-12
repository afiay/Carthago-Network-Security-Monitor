# LAN Device ARP Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Discover awake same-subnet IPv4 devices, including phones that block ping, in the selected Npcap adapter's selector.

**Architecture:** The selector sends and captures Ethernet ARP through its already-selected Npcap adapter, using two bounded passes and a short reply window; packet validation turns replies into primary peer evidence. The Windows ARP resolver remains the injectable fallback for non-selector discovery, and both paths feed the existing selector and labeling pipeline.

**Tech Stack:** C# 12, .NET 8 WPF, `iphlpapi!SendARP`, xUnit

**Spec:** `docs/superpowers/specs/2026-11-12-lan-device-arp-discovery-design.md`

## Global Constraints

- Windows target remains `net8.0-windows10.0.19041.0`.
- Discovery remains IPv4-only, limited to directly connected private/link-local subnets and at most 512 targets.
- Add no package dependencies.
- Never perform Git operations or add co-authorship metadata.

## Review Focus

- A phone returns a unicast MAC but no ICMP reply: include it as a selectable peer with ARP-only evidence.
- Multiple local adapters can reach overlapping-looking private ranges: pass the selected adapter's exact source IPv4 to every ARP probe.
- A native probe fails, returns an invalid MAC length, or returns a multicast/broadcast MAC: ignore that target without failing the scan.
- Cancellation occurs during the bounded scan: stop scheduling useful work and surface cancellation without corrupting results.
- Narrow subnet boundaries and the local address: retain existing network, broadcast, and self exclusions.

---

### Task 1: Interface-bound Windows ARP resolver

**Files:**
- Create: `Carthago/Services/WindowsArpProbe.cs`
- Test: `Carthago.Tests/WindowsArpProbeTests.cs`

**Interfaces:**
- Produces: `internal interface IArpProbe` with `PhysicalAddress? Resolve(IPAddress destination, IPAddress source)`.
- Produces: `internal sealed class WindowsArpProbe : IArpProbe` using `SendARP`.

- [ ] **Step 1: Write failing tests** for IPv6 rejection, failed native return codes, invalid physical-address lengths, and normalized unicast MAC output through an injectable native-call seam.
- [ ] **Step 2: Run** `dotnet test Carthago.Tests/Carthago.Tests.csproj --no-restore --filter FullyQualifiedName~WindowsArpProbeTests` and confirm the tests fail because the resolver does not exist.
- [ ] **Step 3: Implement** `IArpProbe` and `WindowsArpProbe` with an internal native-call delegate, `DllImport("iphlpapi.dll")`, selected-source binding, and fail-closed result validation.
- [ ] **Step 4: Re-run the targeted tests** and confirm they pass.

### Task 2: ARP-first scan orchestration

**Files:**
- Modify: `Carthago/Services/LocalLanDiscovery.cs`
- Modify: `Carthago.Tests/LocalLanDiscoveryTests.cs`
- Modify: `Carthago/Services/LanCaptureDiscovery.cs` only if evidence copy needs to distinguish direct ARP from a cached neighbor.

**Interfaces:**
- Consumes: `IArpProbe.Resolve(IPAddress destination, IPAddress source)` from Task 1.
- Produces: existing `LocalLanDiscovery.ScanAsync(...)` behavior enriched with direct ARP neighbors.

- [ ] **Step 1: Write a failing scan-core test** whose fake ARP probe returns `02:11:22:33:44:55` for `192.168.1.42` while fake ICMP returns no reply; assert the result contains that address and MAC and `BuildPeers` makes it selectable.
- [ ] **Step 2: Add failing tests** proving every probe receives the selected interface source address, an ARP failure is omitted, cancellation is propagated, and existing narrow-subnet exclusions remain intact.
- [ ] **Step 3: Run** the two LAN discovery test classes and confirm the new tests fail for the missing ARP-first behavior.
- [ ] **Step 4: Extract an internal injectable scan core** that accepts interfaces, `IArpProbe`, ping, and neighbor-cache delegates while preserving the public `ScanAsync` signature.
- [ ] **Step 5: Implement bounded ARP-first probing** and ping only resolved peers; merge direct results with the scoped cache without allowing stale cache data to overwrite fresh MAC evidence.
- [ ] **Step 6: Re-run the targeted LAN discovery tests** and confirm they pass.

### Task 3: Verification

**Files:**
- Modify only if verification exposes a defect in the planned behavior.

**Interfaces:**
- Consumes: completed ARP resolver and scan pipeline.
- Produces: verified build and discovery behavior.

- [ ] **Step 1: Run** `dotnet test Carthago.Tests/Carthago.Tests.csproj --no-restore` and report every failure by name.
- [ ] **Step 2: Run** `dotnet build DOTNET.sln --no-restore` and require zero compilation errors.
- [ ] **Step 3: Invoke the real discovery path against the active Wi-Fi adapter** and confirm it returns peers with MAC evidence without requiring ICMP replies; report environmental limits such as client isolation.
