// SPDX-License-Identifier: MIT
// File: Services/PacketHandler.cs
// Fast-path L2/L3/L4 classifier using ReadOnlySpan<byte> with span-routed L7 parsers.
// Falls back to PacketDotNet ONLY when deep parse is unavoidable.
// Normalizes naive TCP reassembly assumptions for early bytes (drop tiny/overlap).

using SharpPcap;
using Carthago.Models;
using Carthago.Services.Flow;
using Carthago.Services.Fingerprints;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PacketDotNet; // used only on guarded fallback

namespace Carthago.Services
{
    public class PacketHandler
    {
        // --- Reassembly heuristics for "early-bytes-only" detectors (TLS ClientHello, HTTP request line, etc.)
        private const int MaxInspectBytesPerDir = 4096;
        private const int MinUsefulSegment = 8; // drop tiny fragments unless they start a known signature
        private readonly Dictionary<FlowKey, TcpStreamState> _tcp = new();

        private sealed class TcpStreamState
        {
            public DirectionState C2S { get; } = new();
            public DirectionState S2C { get; } = new();
        }
        private sealed class DirectionState
        {
            public bool Init;
            public uint NextSeq;
            public int Collected;
            public bool Invalid; // overlap/gap beyond our simple policy
        }

        public TrafficRecord? ParsePacket(PacketCapture e)
        {
            try
            {
                var raw = e.GetPacket();
                if (raw?.Data == null || raw.Data.Length < 14)
                    return null;

                ReadOnlySpan<byte> frame = raw.Data;

                // ====== L2: Ethernet (with VLAN awareness) ======
                string macDst = MacToString(frame.Slice(0, 6));
                string macSrc = MacToString(frame.Slice(6, 6));

                int off = 12;
                ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(off, 2));
                off += 2;

                // VLAN tags (802.1Q/AD stacked)
                while (etherType == 0x8100 || etherType == 0x88A8)
                {
                    if (off + 2 > frame.Length) return null;
                    // skip TCI (2) and read next EtherType
                    off += 2;
                    if (off + 2 > frame.Length) return null;
                    etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(off, 2));
                    off += 2;
                }

                // ====== L3: IPv4 / IPv6 ======
                bool isIPv4 = etherType == 0x0800;
                bool isIPv6 = etherType == 0x86DD;

                if (!isIPv4 && !isIPv6)
                {
                    // Nothing to do for non-IP on fast path. No fallback needed.
                    return null;
                }

                string srcIp, dstIp, ttlStr, ipVersionStr;
                int ipPayloadLen;
                byte l4Proto;
                int l4Offset;

                if (isIPv4)
                {
                    if (off + 20 > frame.Length) return null;
                    byte vihl = frame[off];
                    int ihl = (vihl & 0x0F) * 4;
                    if ((vihl >> 4) != 4 || ihl < 20 || off + ihl > frame.Length) return null;

                    ushort totalLen = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(off + 2, 2));
                    byte ttl = frame[off + 8];
                    l4Proto = frame[off + 9];

                    if (off + totalLen > frame.Length) totalLen = (ushort)Math.Max(ihl, frame.Length - off);

                    srcIp = new IPAddress(frame.Slice(off + 12, 4).ToArray()).ToString();
                    dstIp = new IPAddress(frame.Slice(off + 16, 4).ToArray()).ToString();

                    ttlStr = ttl.ToString();
                    ipVersionStr = "4";
                    l4Offset = off + ihl;
                    ipPayloadLen = Math.Max(0, totalLen - ihl);
                }
                else
                {
                    // IPv6 (basic extension-header walk; drop non-first fragments)
                    if (off + 40 > frame.Length) return null;
                    if ((frame[off] >> 4) != 6) return null;

                    ushort payloadLen = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(off + 4, 2));
                    byte nextHeader = frame[off + 6];
                    byte hopLimit = frame[off + 7];

                    srcIp = new IPAddress(frame.Slice(off + 8, 16).ToArray()).ToString();
                    dstIp = new IPAddress(frame.Slice(off + 24, 16).ToArray()).ToString();

                    ttlStr = hopLimit.ToString();
                    ipVersionStr = "6";

                    int cursor = off + 40;
                    int remaining = Math.Min(payloadLen, (ushort)Math.Max(0, frame.Length - cursor));
                    // Minimal extension skip for common headers
                    for (int i = 0; i < 4; i++)
                    {
                        // Fragment header (44) => drop non-first fragments
                        if (nextHeader == 44)
                        {
                            if (remaining < 8) return null;
                            ushort fragOffFlags = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(cursor + 2, 2));
                            int fragOffset8 = (fragOffFlags >> 3) & 0x1FFF;
                            byte nh = frame[cursor];
                            if (fragOffset8 != 0) return null; // not the first fragment -> drop on fast path
                            nextHeader = nh;
                            int hdrLen = 8;
                            cursor += hdrLen; remaining -= hdrLen;
                            continue;
                        }
                        // Hop-by-hop (0), Routing (43), DestOpts(60), AH(51) – skip length-based
                        if (nextHeader is 0 or 43 or 60 or 51)
                        {
                            if (remaining < 8) return null;
                            byte hdrExtLen = frame[cursor + 1]; // in 8-octet units (not counting first 8 octets)
                            int hdrLen = (hdrExtLen + 1) * 8;
                            byte nh = frame[cursor];
                            if (hdrLen > remaining) return null;
                            nextHeader = nh;
                            cursor += hdrLen; remaining -= hdrLen;
                            continue;
                        }
                        break;
                    }

                    l4Proto = nextHeader;
                    l4Offset = cursor;
                    ipPayloadLen = Math.Max(0, Math.Min(remaining, frame.Length - cursor));
                }

                // ====== L4: TCP / UDP / ICMP ======
                int? sport = null, dport = null;
                string protoLabel;
                bool isTcp = false, isUdp = false;
                ushort? tcpFlagsField = null;
                ushort? icmpTypeCode = null;
                int? l4PayloadLen = null;
                ReadOnlySpan<byte> l4Payload = ReadOnlySpan<byte>.Empty;
                int tcpDataOffset = 0;
                uint seq = 0, ack = 0;
                bool tcpSyn = false, tcpAck = false;

                switch (l4Proto)
                {
                    case 6: // TCP
                        {
                            if (l4Offset + 20 > frame.Length) return null;
                            isTcp = true;
                            sport = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(l4Offset, 2));
                            dport = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(l4Offset + 2, 2));
                            seq = BinaryPrimitives.ReadUInt32BigEndian(frame.Slice(l4Offset + 4, 4));
                            ack = BinaryPrimitives.ReadUInt32BigEndian(frame.Slice(l4Offset + 8, 4));
                            byte doRes = frame[l4Offset + 12];
                            byte flags = frame[l4Offset + 13];
                            tcpDataOffset = (doRes >> 4) * 4;
                            tcpSyn = (flags & 0x02) != 0;
                            tcpAck = (flags & 0x10) != 0;

                            // Include NS flag from low bit of doRes if you want 9+ flags
                            tcpFlagsField = (ushort)((doRes & 0x01) << 8 | flags);

                            if (tcpDataOffset < 20 || l4Offset + tcpDataOffset > frame.Length)
                                tcpDataOffset = 20;

                            int tcpAvail = Math.Max(0, Math.Min(ipPayloadLen - tcpDataOffset, frame.Length - (l4Offset + tcpDataOffset)));
                            l4Payload = frame.Slice(l4Offset + tcpDataOffset, Math.Max(0, tcpAvail));
                            l4PayloadLen = tcpAvail;

                            protoLabel = "TCP";
                            break;
                        }

                    case 17: // UDP
                        {
                            if (l4Offset + 8 > frame.Length) return null;
                            isUdp = true;
                            sport = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(l4Offset, 2));
                            dport = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(l4Offset + 2, 2));
                            ushort udpLen = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(l4Offset + 4, 2));
                            int payloadLen = Math.Max(0, Math.Min(udpLen - 8, frame.Length - (l4Offset + 8)));
                            l4Payload = frame.Slice(l4Offset + 8, payloadLen);
                            l4PayloadLen = payloadLen;
                            protoLabel = "UDP";
                            break;
                        }

                    case 1: // ICMPv4
                        {
                            if (l4Offset + 2 > frame.Length) return null;
                            icmpTypeCode = (ushort)((frame[l4Offset] << 8) | frame[l4Offset + 1]);
                            l4PayloadLen = Math.Max(0, ipPayloadLen);
                            protoLabel = "ICMP";
                            break;
                        }

                    case 58: // ICMPv6
                        {
                            if (l4Offset + 2 > frame.Length) return null;
                            icmpTypeCode = (ushort)((frame[l4Offset] << 8) | frame[l4Offset + 1]);
                            l4PayloadLen = Math.Max(0, ipPayloadLen);
                            protoLabel = "ICMPv6";
                            break;
                        }

                    default:
                        return null; // Fast path only tracks TCP/UDP/ICMP
                }

                // ====== Build minimal record (header-only summary) ======
                string timestamp = DateTime.Now.ToString("HH:mm:ss");

                var rec = new TrafficRecord
                {
                    Timestamp = timestamp,
                    Source = srcIp,
                    Destination = dstIp,
                    Protocol = protoLabel,
                    ProtocolVersion = ipVersionStr,
                    TTL = ttlStr,
                    Length = isIPv4 ? ipPayloadLen + (ipVersionStr == "4" ? 20 : 40) : ipPayloadLen, // UI legacy
                    Info = string.Empty,

                    SourcePort = sport,
                    DestinationPort = dport,
                    Flags = isTcp ? FlagsToString(tcpFlagsField ?? 0) : null,
                    Checksum = "N/A",
                    MacSource = macSrc,
                    MacDestination = macDst,

                    IsTcp = isTcp,
                    IsUdp = isUdp,

                    // New header-summary fields
                    IpVersion = ipVersionStr == "4" ? 4 : 6,
                    TcpFlags = tcpFlagsField,
                    IcmpTypeCode = icmpTypeCode,
                    L4Len = l4PayloadLen,

                    // Defaults (nullable-friendly)
                    IsVpn = null,
                    IsProxy = null,
                };

                // Service guess from ports
                rec.ApplicationService = ResolveService(protoLabel, sport, dport);

                // Local process + VPN/Proxy enrichment (unchanged policy)
                var det = VpnProxyResolver.CheckIp(srcIp);
                rec.IsVpn = det.IsVpn;
                rec.IsProxy = det.IsProxy;
                rec.NetworkType = det.NetworkType;

                WindowsProcessResolver.ProcessInfo? proc = null;
                if (IpUtils.IsPrivateIp(srcIp) || IpUtils.IsPrivateIp(dstIp))
                {
                    proc = WindowsProcessResolver.ResolveProcess(srcIp, sport, dstIp, dport, protoLabel);
                    rec.ProcessId = proc?.ProcessId ?? 0;
                    rec.ProcessName = proc?.ProcessName ?? "Unknown";
                    if (proc != null) AppendInfo(rec, $"\nLocal Process: {proc.ProcessName} (PID {proc.ProcessId})");
                }

                // ====== TCP latency + JA4(T) from SYN/SYN-ACK ======
                if (isTcp)
                {
                    var fk = new FlowKey(srcIp, sport ?? 0, dstIp, dport ?? 0, "TCP");

                    if (tcpSyn && !tcpAck) // client SYN
                    {
                        LatencyTracker.NoteSyn(fk, DateTime.UtcNow);
                        // rec.TcpJa4t = TcpJa4T.FromSyn(...); // if available in your codebase
                        rec.TcpJa4t = rec.Ja4T ?? rec.Ja4T;
                        InitSeq(_tcp, fk, clientToServer: true, seqPlus1: seq + 1);
                    }
                    else if (tcpSyn && tcpAck) // server SYN-ACK
                    {
                        LatencyTracker.NoteSynAck(fk.Reverse(), DateTime.UtcNow);
                        // rec.TcpJa4ts = TcpJa4T.FromSynAck(...);
                        rec.TcpJa4ts = rec.Ja4TS ?? rec.Ja4TS;
                        InitSeq(_tcp, fk, clientToServer: false, seqPlus1: seq + 1);
                    }
                }

                // ====== L7 — span-routed, avoid double parse ======
                try
                {
                    if (isTcp)
                    {
                        // Normalize tiny fragments/overlaps for early bytes
                        var fk = new FlowKey(srcIp, sport ?? 0, dstIp, dport ?? 0, "TCP");
                        bool c2s = IsClientToServer(rec);
                        if (ShouldAcceptSegment(fk, c2s, seq, l4Payload, l4PayloadLen ?? 0, out ReadOnlySpan<byte> normPayload))
                        {
                            // -------- HTTP --------
                            if (normPayload.Length >= 4 && HttpLight.TryParseHttp(normPayload, out var http))
                            {
                                rec.ApplicationProtocol = "HTTP";
                                rec.HttpMethod = http.Method ?? rec.HttpMethod;
                                rec.HttpUri = http.Path ?? rec.HttpUri;
                                rec.HttpHost = http.Host ?? rec.HttpHost;
                                rec.HttpUserAgent = http.UserAgent ?? rec.HttpUserAgent;
                                rec.HttpRequestHeaders = http.JoinedHeaderLines ?? rec.HttpRequestHeaders;

                                var (readable, tag) = HttpJa4H.Compute(http.Method, http.HttpVersion, http.HeaderNames, http.UserAgent);
                                rec.HttpJa4h = $"{readable}|{tag}";

                                LatencyTracker.NoteFirstDataClient(new FlowKey(srcIp, sport ?? 0, dstIp, dport ?? 0, "TCP"), DateTime.UtcNow);
                                AppendInfo(rec, $"[HTTP host={rec.HttpHost ?? "-"} ua={(rec.HttpUserAgent ?? "-")}]");
                            }

                            // -------- TLS -------- (client/server hello + cert)
                            if (normPayload.Length >= 9 && TlsLight.LooksLikeTlsRecord(normPayload))
                            {
                                var fk2 = new FlowKey(srcIp, sport ?? 0, dstIp, dport ?? 0, "TCP");
                                bool clientToServer = c2s;
                                if (clientToServer)
                                {
                                    HandshakeBuffer.AddClientBytes(fk2, normPayload.ToArray()); // buffer owns copy
                                    var ch = HandshakeBuffer.TryGetClientHello(fk2);
                                    if (!ch.IsEmpty)
                                    {
                                        rec.ApplicationProtocol = "TLS";
                                        if (TlsLight.TryParseClientHello(ch, out var tlsInfo))
                                        {
                                            rec.Sni = tlsInfo.ServerName ?? rec.Sni;
                                            rec.Alpn = tlsInfo.Alpn ?? rec.Alpn;
                                            rec.TlsVersion = tlsInfo.VersionLabel ?? rec.TlsVersion;
                                            rec.Ja3 = tlsInfo.Ja3 ?? rec.Ja3;
                                        }
                                        rec.TlsJa4 = TlsJa4.FromClientHello(ch);
                                        AppendInfo(rec, $"[TLS sni={rec.Sni ?? "-"} alpn={rec.Alpn ?? "-"}]");
                                    }
                                }
                                else
                                {
                                    HandshakeBuffer.AddServerBytes(fk2.Reverse(), normPayload.ToArray());
                                    HandshakeBuffer.TryGetServerHellos(fk2.Reverse(), out var sh, out var cert);
                                    if (!sh.IsEmpty)
                                        rec.TlsJa4s = TlsJa4.FromServerHello(sh);

                                    if (!cert.IsEmpty)
                                    {
                                        TryExtractCert(rec, cert);
                                        LatencyTracker.NoteFirstDataServer(new FlowKey(srcIp, sport ?? 0, dstIp, dport ?? 0, "TCP"), DateTime.UtcNow);
                                    }

                                    var (l, ls) = LatencyTracker.GetLatencyFingerprints(new FlowKey(dstIp, dport ?? 0, srcIp, sport ?? 0, "TCP").Reverse());
                                    if (!string.IsNullOrEmpty(l)) rec.Ja4L = l;
                                    if (!string.IsNullOrEmpty(ls)) rec.Ja4LS = ls;
                                }
                            }

                            // -------- SSH --------
                            if ((sport == 22 || dport == 22) && normPayload.Length > 0)
                            {
                                string? banner = null;
                                try
                                {
                                    var s = Encoding.ASCII.GetString(normPayload);
                                    if (s.StartsWith("SSH-")) banner = s.Split('\n')[0].Trim();
                                }
                                catch { /* ignore */ }

                                string? kex = null, enc = null, mac = null, comp = null;
                                rec.SshJa4 = SshJa4SSH.From(banner, kex, enc, mac);
                                rec.Hassh = SshJa4SSH.Hassh(kex, enc, mac, comp);
                            }
                        }
                    }
                    else if (isUdp)
                    {
                        // -------- QUIC --------
                        if (l4Payload.Length >= 6 && QuicLight.TryDetectQuic(l4Payload, out var quic))
                        {
                            rec.ApplicationProtocol = "QUIC";
                            rec.IsQuic = true;
                            rec.QuicVersion = quic.VersionLabel ?? rec.QuicVersion;
                            AppendInfo(rec, $"[QUIC v={rec.QuicVersion ?? "-"}]");
                        }

                        // -------- DNS (UDP or TCP path compatible) --------
                        if ((rec.DestinationPort == 53 || rec.SourcePort == 53) &&
                            DnsLight.TryParse(l4Payload, isTcp: false, out var dns))
                        {
                            rec.ApplicationService = "DNS";
                            rec.DnsQname = dns.QName ?? rec.DnsQname;
                            rec.DnsQtype = dns.QType ?? rec.DnsQtype;
                            rec.DnsRcode = dns.Rcode ?? rec.DnsRcode;
                            rec.DnsIsResponse = dns.IsResponse;
                            AppendInfo(rec, $"[DNS {(dns.IsResponse ? "ans" : "q")}={rec.DnsQname ?? "-"} {rec.DnsQtype ?? "?"}]");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[PacketHandler] L7 parse error: {ex.Message}");
                }

                // Fallback: Only when span path cannot classify but we still want deep L7 (rare).
                // (Kept for future deep-detectors; currently our span parsers cover HTTP/TLS/DNS/SSH.)
                // If you decide to always avoid fallback, you can remove the below block.
                if (rec.ApplicationProtocol == null &&
                    rec.IsTcp && l4Payload.Length > 0 &&
                    NeedsDeepFallback(rec))
                {
                    try
                    {
                        var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
                        var tcp = packet.Extract<TcpPacket>();
                        var udp = packet.Extract<UdpPacket>();
                        var payload = tcp?.PayloadData ?? udp?.PayloadData ?? Array.Empty<byte>();
                        // Route to the same span-based parsers to keep behavior identical:
                        if (payload.Length >= 4 && HttpLight.TryParseHttp(payload, out var http))
                        {
                            rec.ApplicationProtocol = "HTTP";
                            rec.HttpMethod = http.Method ?? rec.HttpMethod;
                            rec.HttpUri = http.Path ?? rec.HttpUri;
                            rec.HttpHost = http.Host ?? rec.HttpHost;
                            rec.HttpUserAgent = http.UserAgent ?? rec.HttpUserAgent;
                            rec.HttpRequestHeaders = http.JoinedHeaderLines ?? rec.HttpRequestHeaders;
                            var (readable, tag) = HttpJa4H.Compute(http.Method, http.HttpVersion, http.HeaderNames, http.UserAgent);
                            rec.HttpJa4h = $"{readable}|{tag}";
                        }
                        else if (payload.Length >= 9 && TlsLight.LooksLikeTlsRecord(payload))
                        {
                            var fk = new FlowKey(rec.Source!, rec.SourcePort ?? 0, rec.Destination!, rec.DestinationPort ?? 0, "TCP");
                            HandshakeBuffer.AddClientBytes(fk, payload);
                            var ch = HandshakeBuffer.TryGetClientHello(fk);
                            if (!ch.IsEmpty)
                            {
                                rec.ApplicationProtocol = "TLS";
                                if (TlsLight.TryParseClientHello(ch, out var tlsInfo))
                                {
                                    rec.Sni = tlsInfo.ServerName ?? rec.Sni;
                                    rec.Alpn = tlsInfo.Alpn ?? rec.Alpn;
                                    rec.TlsVersion = tlsInfo.VersionLabel ?? rec.TlsVersion;
                                    rec.Ja3 = tlsInfo.Ja3 ?? rec.Ja3;
                                }
                                rec.TlsJa4 = TlsJa4.FromClientHello(ch);
                            }
                        }
                    }
                    catch { /* ignore deep fallback errors */ }
                }

                // Final info line (protocol and 5-tuple)
                if (string.IsNullOrEmpty(rec.Info))
                {
                    var sp = rec.SourcePort.HasValue ? $":{rec.SourcePort}" : "";
                    var dp = rec.DestinationPort.HasValue ? $":{rec.DestinationPort}" : "";
                    rec.Info = $"{rec.Protocol} {rec.Source}{sp} → {rec.Destination}{dp}";
                }

                return rec;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Packet parsing error: {ex.Message}");
                return null;
            }
        }

        // Heuristic: Only fall back if you plan additional deep detectors beyond HTTP/TLS/DNS/SSH.
        private static bool NeedsDeepFallback(TrafficRecord r) => false;

        private static void TryExtractCert(TrafficRecord rec, ReadOnlySpan<byte> certMsg)
        {
            // TLS record header (5) + handshake header (4)
            var span = certMsg.Slice(5);
            if (span.Length < 4 || span[0] != 0x0B) return;
            int hsLen = (span[1] << 16) | (span[2] << 8) | span[3];
            var body = span.Slice(4, Math.Min(hsLen, span.Length - 4));
            if (body.Length < 7) return;
            int p = 3; // skip cert_list_len(3)
            if (p + 3 > body.Length) return;
            int certLen = (body[p] << 16) | (body[p + 1] << 8) | body[p + 2];
            p += 3;
            if (p + certLen > body.Length) return;
            var der = body.Slice(p, certLen).ToArray();
            rec.TlsJa4x = X509Ja4X.FromCertificateDer(der);
            try
            {
                var x = new X509Certificate2(der);
                rec.CertIssuer = x.Issuer;
                rec.CertSubject = x.Subject;
                rec.CertValidFrom = x.NotBefore.ToUniversalTime();
                rec.CertValidTo = x.NotAfter.ToUniversalTime();
            }
            catch { /* ignore */ }
        }

        private static void InitSeq(Dictionary<FlowKey, TcpStreamState> map, FlowKey fk, bool clientToServer, uint seqPlus1)
        {
            if (!map.TryGetValue(fk, out var st)) map[fk] = st = new TcpStreamState();
            var dir = clientToServer ? st.C2S : st.S2C;
            dir.Init = true;
            dir.NextSeq = seqPlus1;
            dir.Collected = 0;
            dir.Invalid = false;
        }

        private bool ShouldAcceptSegment(FlowKey fk, bool clientToServer, uint segSeq, ReadOnlySpan<byte> payload, int payloadLen, out ReadOnlySpan<byte> normalized)
        {
            normalized = payload;
            if (!_tcp.TryGetValue(fk, out var st))
                _tcp[fk] = st = new TcpStreamState();

            var dir = clientToServer ? st.C2S : st.S2C;

            // if not initialized (no SYN observed), accept only if payload is large enough (avoid tiny fragment noise)
            if (!dir.Init)
            {
                if (payloadLen < MinUsefulSegment && !LooksLikeHandshakePrefix(payload))
                    return false;
                dir.Init = true;
                dir.NextSeq = segSeq + (uint)payloadLen;
                dir.Collected = Math.Min(payloadLen, MaxInspectBytesPerDir);
                return true;
            }

            // Overlap/gap handling for early stream assembly: allow perfect contiguity; small overlaps are trimmed
            if (segSeq == dir.NextSeq)
            {
                dir.NextSeq += (uint)payloadLen;
                dir.Collected = Math.Min(MaxInspectBytesPerDir, dir.Collected + payloadLen);
                return true;
            }

            if (segSeq < dir.NextSeq)
            {
                // overlap amount
                uint overlap = dir.NextSeq - segSeq;
                if (overlap >= payloadLen)
                    return false; // fully duplicate
                if (overlap <= 3)
                {
                    normalized = payload.Slice((int)overlap);
                    dir.NextSeq += (uint)(payloadLen - overlap);
                    dir.Collected = Math.Min(MaxInspectBytesPerDir, dir.Collected + payloadLen - (int)overlap);
                    return true;
                }
                // too messy -> drop for fast path
                dir.Invalid = true;
                return false;
            }

            // gap -> drop fast-path view (await re-sync on future SYN)
            dir.Invalid = true;
            return false;
        }

        private static bool LooksLikeHandshakePrefix(ReadOnlySpan<byte> p)
        {
            if (p.Length == 0) return false;
            if (p[0] == 0x16) return true; // TLS Handshake record
            if (p.Length >= 4)
            {
                // crude HTTP guess
                var s = Encoding.ASCII.GetString(p.Slice(0, Math.Min(4, p.Length)));
                if (s is "GET " or "POST" or "HEAD" or "PUT " or "HTTP") return true;
            }
            return false;
        }

        private static string FlagsToString(ushort tf)
        {
            // tf = NS(0x100) + flagsByte
            var list = new List<string>(9);
            if ((tf & 0x100) != 0) list.Add("NS");
            if ((tf & 0x02) != 0) list.Add("SYN");
            if ((tf & 0x10) != 0) list.Add("ACK");
            if ((tf & 0x01) != 0) list.Add("FIN");
            if ((tf & 0x04) != 0) list.Add("RST");
            if ((tf & 0x08) != 0) list.Add("PSH");
            if ((tf & 0x20) != 0) list.Add("URG");
            if ((tf & 0x40) != 0) list.Add("ECE");
            if ((tf & 0x80) != 0) list.Add("CWR");
            return string.Join(", ", list);
        }

        private static bool IsClientToServer(TrafficRecord r)
        {
            // Heuristic: SYN without ACK is always client->server; otherwise use lower ephemeral source port convention
            if (!string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)) return true;
            if (r.TcpFlags.HasValue && (r.TcpFlags.Value & 0x02) != 0 && (r.TcpFlags.Value & 0x10) == 0) return true;
            if (r.SourcePort.HasValue && r.DestinationPort.HasValue)
                return r.SourcePort < r.DestinationPort;
            return true;
        }

        private static string MacToString(ReadOnlySpan<byte> mac)
        {
            if (mac.Length < 6) return "N/A";
            var sb = new StringBuilder(17);
            for (int i = 0; i < 6; i++)
            {
                if (i > 0) sb.Append(':');
                sb.Append(mac[i].ToString("X2"));
            }
            return sb.ToString();
        }

        private string ResolveService(string protocol, int? sourcePort, int? destinationPort)
        {
            string destService = destinationPort.HasValue ? PortServiceResolver.GetServiceName(destinationPort.Value, protocol) : "Unknown";
            if (!string.Equals(destService, "Unknown", StringComparison.OrdinalIgnoreCase))
                return destService;

            string srcService = sourcePort.HasValue ? PortServiceResolver.GetServiceName(sourcePort.Value, protocol) : "Unknown";
            return srcService;
        }

        private static void AppendInfo(TrafficRecord rec, string tag)
        {
            if (string.IsNullOrWhiteSpace(tag)) return;
            if (string.IsNullOrEmpty(rec.Info)) rec.Info = tag;
            else if (!rec.Info.Contains(tag, StringComparison.OrdinalIgnoreCase))
                rec.Info += " " + tag;
        }
    }

    // ===========================
    // Lightweight parsers (existing) – kept as-is and driven from span pipeline
    // ===========================

    internal static class HttpLight
    {
        private static readonly byte[] CRLF = new byte[] { 0x0D, 0x0A };

        internal sealed class HttpInfo
        {
            public string? Method { get; init; }
            public string? Path { get; init; }
            public string? Host { get; init; }
            public string? UserAgent { get; init; }
            public string? HttpVersion { get; init; }
            public List<string> HeaderNames { get; init; } = new();
            public string? JoinedHeaderLines { get; init; }
        }

        public static bool TryParseHttp(ReadOnlySpan<byte> data, out HttpInfo info)
        {
            info = new HttpInfo();
            int lineEnd = data.IndexOf(CRLF);
            if (lineEnd < 0 || lineEnd > 8192) return false;

            var firstLine = data.Slice(0, lineEnd);
            if (TryParseRequestLine(firstLine, out var method, out var path, out var vers))
            {
                info = ParseHeaders(data, lineEnd + CRLF.Length, method, path, vers);
                return true;
            }

            if (StartsWith(firstLine, "HTTP/1.") || StartsWith(firstLine, "HTTP/2"))
            {
                info = ParseHeaders(data, lineEnd + CRLF.Length, null, null, ToAscii(firstLine.Slice(0, Math.Min(8, firstLine.Length))));
                return info.Host != null || info.UserAgent != null;
            }

            return false;
        }

        private static HttpInfo ParseHeaders(ReadOnlySpan<byte> data, int offset, string? method, string? path, string? httpVersion)
        {
            string? host = null, ua = null;
            int idx = offset;
            var headerNames = new List<string>();
            var sbJoin = new StringBuilder();

            while (idx < data.Length)
            {
                int end = data.Slice(idx).IndexOf(CRLF);
                if (end < 0) break;
                if (end == 0) break; // end of headers

                var line = data.Slice(idx, end);
                idx += end + CRLF.Length;

                int colon = line.IndexOf((byte)':');
                if (colon > 0)
                {
                    var name = ToAscii(line.Slice(0, colon));
                    headerNames.Add(name);
                    var val = TrimHeaderValue(line, colon + 1);
                    sbJoin.Append(name).Append(": ").Append(val).Append("\r\n");
                    if (name.Equals("Host", StringComparison.OrdinalIgnoreCase)) host = val;
                    else if (name.Equals("User-Agent", StringComparison.OrdinalIgnoreCase)) ua = val;
                }
            }
            return new HttpInfo
            {
                Method = method,
                Path = path,
                Host = host,
                UserAgent = ua,
                HttpVersion = httpVersion,
                JoinedHeaderLines = sbJoin.ToString(),
                HeaderNames = headerNames
            };
        }

        private static bool TryParseRequestLine(ReadOnlySpan<byte> line, out string? method, out string? path, out string? ver)
        {
            method = null; path = null; ver = null;
            int sp = line.IndexOf((byte)' ');
            if (sp <= 0 || sp > 16) return false;
            method = ToAscii(line.Slice(0, sp));

            var rest = line.Slice(sp + 1);
            int sp2 = rest.IndexOf((byte)' ');
            if (sp2 <= 0) return false;
            path = ToAscii(rest.Slice(0, sp2));
            ver = ToAscii(rest.Slice(sp2 + 1));
            return true;
        }

        private static string TrimHeaderValue(ReadOnlySpan<byte> line, int colonIndexPlusOne)
        {
            var v = line.Slice(colonIndexPlusOne);
            v = TrimStartSpacesTabs(v);
            return ToAscii(v);
        }

        private static ReadOnlySpan<byte> TrimStartSpacesTabs(ReadOnlySpan<byte> s)
        {
            int i = 0;
            while (i < s.Length)
            {
                byte b = s[i];
                if (b == (byte)' ' || b == (byte)'\t') { i++; continue; }
                break;
            }
            return s.Slice(i);
        }

        private static bool StartsWith(ReadOnlySpan<byte> span, string ascii) => span.StartsWith(Encoding.ASCII.GetBytes(ascii));
        private static string ToAscii(ReadOnlySpan<byte> span) => Encoding.ASCII.GetString(span);
    }

    internal static class TlsLight
    {
        internal sealed class TlsInfo
        {
            public string? ServerName { get; set; }
            public string? Alpn { get; set; }
            public string? VersionLabel { get; set; }
            public string? Ja3 { get; set; }
        }

        public static bool LooksLikeTlsRecord(ReadOnlySpan<byte> data) => data.Length >= 5 && data[0] == 0x16;

        public static bool TryParseClientHello(ReadOnlySpan<byte> tlsRecord, out TlsInfo info)
        {
            info = new TlsInfo();

            if (tlsRecord.Length < 5 || tlsRecord[0] != 0x16) return false;
            ushort recLen = BinaryPrimitives.ReadUInt16BigEndian(tlsRecord.Slice(3, 2));
            if (5 + recLen > tlsRecord.Length) return false;
            var body = tlsRecord.Slice(5, recLen);
            if (body.Length < 4 || body[0] != 0x01) return false;

            return TryParseClientHelloBody(body, out info);
        }

        private static bool TryParseClientHelloBody(ReadOnlySpan<byte> body, out TlsInfo info)
        {
            info = new TlsInfo();
            int hsLen = (body[1] << 16) | (body[2] << 8) | body[3];
            if (hsLen + 4 > body.Length) return false;

            var span = body.Slice(4);
            if (span.Length < 2 + 32) return false;

            ushort legacyVersion = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(0, 2));
            info.VersionLabel = legacyVersion switch
            {
                0x0301 => "TLS1.0",
                0x0302 => "TLS1.1",
                0x0303 => "TLS1.2",
                0x0304 => "TLS1.3*",
                _ => $"0x{legacyVersion:X4}"
            };

            int idx = 2 + 32;
            if (idx >= span.Length) return false;

            byte sidLen = span[idx++]; idx += sidLen;

            if (idx + 2 > span.Length) return false;
            ushort csLen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx, 2)); idx += 2;
            var ciphers = span.Slice(idx, csLen); idx += csLen;

            if (idx >= span.Length) return false;
            byte compLen = span[idx++]; idx += compLen;

            var extTypes = new List<ushort>();
            var groups = new List<ushort>();
            var ecpf = new List<byte>();
            string? sni = null, alpn = null;

            if (idx + 2 <= span.Length)
            {
                ushort extTotal = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx, 2)); idx += 2;
                if (idx + extTotal <= span.Length)
                {
                    int exEnd = idx + extTotal;
                    while (idx + 4 <= exEnd)
                    {
                        ushort etype = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx, 2));
                        ushort elen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx + 2, 2));
                        idx += 4;
                        if (idx + elen > exEnd) break;
                        var extData = span.Slice(idx, elen);
                        idx += elen;

                        extTypes.Add(etype);

                        if (etype == 0x0000) // server_name
                        {
                            if (extData.Length >= 5)
                            {
                                int p = 2;
                                if (p + 3 <= extData.Length && extData[p] == 0x00)
                                {
                                    ushort nameLen = BinaryPrimitives.ReadUInt16BigEndian(extData.Slice(p + 1, 2));
                                    p += 3;
                                    if (p + nameLen <= extData.Length)
                                        sni = Encoding.ASCII.GetString(extData.Slice(p, nameLen));
                                }
                            }
                        }
                        else if (etype == 0x0010) // ALPN
                        {
                            if (extData.Length >= 3)
                            {
                                int p = 2;
                                if (p < extData.Length)
                                {
                                    byte l = extData[p++];
                                    if (p + l <= extData.Length)
                                        alpn = Encoding.ASCII.GetString(extData.Slice(p, l));
                                }
                            }
                        }
                        else if (etype == 0x000A) // supported_groups
                        {
                            if (extData.Length >= 2)
                            {
                                int p = 2;
                                while (p + 2 <= extData.Length)
                                {
                                    groups.Add(BinaryPrimitives.ReadUInt16BigEndian(extData.Slice(p, 2)));
                                    p += 2;
                                }
                            }
                        }
                        else if (etype == 0x000B) // ec_point_formats
                        {
                            if (extData.Length >= 1)
                            {
                                int p = 1;
                                while (p < extData.Length) ecpf.Add(extData[p++]);
                            }
                        }
                    }
                }
            }

            info.ServerName = sni;
            info.Alpn = alpn;

            // Legacy JA3 for continuity
            var ver = legacyVersion.ToString();
            var csIds = JoinU16(ciphers);
            var exIds = string.Join("-", extTypes);
            var grpIds = string.Join("-", groups);
            var ecpfIds = string.Join("-", ecpf);
            string ja3Str = $"{ver},{csIds},{exIds},{grpIds},{ecpfIds}";
            info.Ja3 = MD5Hex(ja3Str);
            return true;
        }

        private static string JoinU16(ReadOnlySpan<byte> buf)
        {
            if (buf.Length % 2 != 0) return "";
            var list = new List<ushort>(buf.Length / 2);
            for (int i = 0; i < buf.Length; i += 2)
                list.Add(BinaryPrimitives.ReadUInt16BigEndian(buf.Slice(i, 2)));
            return string.Join("-", list);
        }

        private static string MD5Hex(string s)
        {
            using var md5 = System.Security.Cryptography.MD5.Create();
            var bytes = Encoding.ASCII.GetBytes(s);
            var hash = md5.ComputeHash(bytes);
            var sb = new StringBuilder(hash.Length * 2);
            foreach (var b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }

    internal static class QuicLight
    {
        internal sealed class QuicInfo { public string? VersionLabel { get; set; } }

        public static bool TryDetectQuic(ReadOnlySpan<byte> data, out QuicInfo info)
        {
            info = new QuicInfo();
            if (data.Length < 5) return false;
            if ((data[0] & 0x80) == 0) return false;
            uint version = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(1, 4));
            if (version == 0) return false;
            info.VersionLabel = $"0x{version:X8}";
            return true;
        }
    }

    internal static class DnsLight
    {
        internal sealed class DnsInfo
        {
            public bool IsResponse { get; init; }
            public string? QName { get; init; }
            public string? QType { get; init; }
            public string? Rcode { get; init; }
        }

        public static bool TryParse(ReadOnlySpan<byte> data, bool isTcp, out DnsInfo info)
        {
            info = new DnsInfo();
            int idx = 0;
            if (isTcp)
            {
                if (data.Length < 2) return false;
                ushort len = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(0, 2));
                if (len + 2 > data.Length) return false;
                idx = 2;
            }
            if (idx + 12 > data.Length) return false;

            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(idx + 2, 2));
            bool isResp = (flags & 0x8000) != 0;
            int rcode = flags & 0x000F;
            ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(idx + 4, 2));
            int p = idx + 12;

            string? qname = null;
            ushort qtype = 0;

            if (qdCount > 0)
            {
                if (!TryReadQName(data, p, out qname, out p)) return false;
                if (p + 4 <= data.Length)
                {
                    qtype = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(p, 2));
                    p += 4;
                }
            }

            info = new DnsInfo
            {
                IsResponse = isResp,
                QName = qname,
                QType = QTypeToString(qtype),
                Rcode = RcodeToString(rcode)
            };
            return qname != null;
        }

        private static bool TryReadQName(ReadOnlySpan<byte> data, int start, out string? name, out int next)
        {
            name = null;
            var sb = new StringBuilder(128);
            int p = start;
            int safety = 0;

            while (p < data.Length && safety++ < 128)
            {
                byte len = data[p++];
                if (len == 0) break;

                if ((len & 0xC0) == 0xC0)
                {
                    if (p >= data.Length) { next = start; return false; }
                    byte b2 = data[p++];
                    int ptr = ((len & 0x3F) << 8) | b2;
                    if (!TryReadQName(data, ptr, out var name2, out _)) { next = start; return false; }
                    if (sb.Length > 0) sb.Append('.');
                    sb.Append(name2);
                    name = sb.ToString();
                    next = p;
                    return true;
                }

                if (p + len > data.Length) { next = start; return false; }
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(data.Slice(p, len)));
                p += len;
            }

            name = sb.ToString();
            next = p;
            return true;
        }

        private static string QTypeToString(ushort qtype) => qtype switch
        {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            255 => "ANY",
            _ => qtype == 0 ? "?" : qtype.ToString()
        };

        private static string RcodeToString(int r) => r switch
        {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            _ => r.ToString()
        };
    }

    public static class IpUtils
    {
        public static bool IsPrivateIp(string ip)
        {
            if (!IPAddress.TryParse(ip, out var address)) return false;
            if (IPAddress.IsLoopback(address)) return true;
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (address.IsIPv4MappedToIPv6) return IsPrivateIp(address.MapToIPv4().ToString());
                var b = address.GetAddressBytes();
                if (b[0] == 0xFC || b[0] == 0xFD) return true; // Unique local
                if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true; // link-local
                if (b[0] == 0xFE && (b[1] & 0xC0) == 0xC0) return true; // site-local (deprecated)
                return false;
            }
            var v4 = address.GetAddressBytes();
            return (v4[0] == 10) ||
                   (v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31) ||
                   (v4[0] == 192 && v4[1] == 168) ||
                   (v4[0] == 127) ||
                   (v4[0] == 169 && v4[1] == 254);
        }
    }
}
