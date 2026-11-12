# LAN Device ARP Discovery Design

## Intent



## Goals

- Probe the selected adapter's directly connected IPv4 subnet with interface-bound ARP.
- Add ARP-responsive devices to the selector whether or not they answer ping.
- Keep ICMP replies as additional liveness evidence and retain optional reverse-DNS labels.
- Bound concurrency and the existing maximum target count so discovery remains controlled and cancellable.

## Non-goals and constraints

- Do not claim that a discovered peer is a remote capture agent or that all of its switched traffic is visible locally.
- Do not cross routers, VLANs, or Wi-Fi client-isolation boundaries.
- Keep discovery IPv4-only; do not add dependencies.
- Never perform Git operations or add co-authorship metadata.

## Approaches

- Selected: direct Ethernet ARP request/reply discovery through the already-selected Npcap adapter. A Windows `SendARP` implementation remains available for non-selector discovery, but the selector uses the packet path because native negative resolutions serialize and took about 45 seconds on a `/24`.
- Considered: mDNS/SSDP discovery. It can supply names for advertising devices but misses silent phones and is not a complete same-subnet inventory.
- Considered: retaining the ICMP sweep and merely loosening result filters. That cannot reliably identify ping-blocking devices or bind probes to the chosen adapter.

## Design

Build and parse Ethernet ARP frames with strict IPv4, opcode, target, and unicast-MAC validation, including VLAN-tagged replies. Open the selected Npcap adapter only while monitoring is stopped, send two bounded request passes, collect replies for a fixed window, close the adapter, and pass direct evidence through `LanCaptureDiscovery.BuildPeers` and optional reverse DNS. Keep the Windows ARP resolver and injectable scan core for non-selector discovery and testing.
