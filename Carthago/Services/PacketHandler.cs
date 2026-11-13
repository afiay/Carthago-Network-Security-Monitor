// SPDX-License-Identifier: MIT
// File: Services/PacketHandler.cs
// Fast-path L2/L3/L4 classifier using ReadOnlySpan<byte> with span-routed L7 parsers.
// Strictly bounds checks captured frames and keeps the TCP inspection state bounded.
// Early bytes are inspected; this is not general TCP stream reassembly.

using SharpPcap;
using PacketDotNet;
using Carthago.Models;
using Carthago.Engine.Rules;
using Carthago.Services.Flow;
using Carthago.Services.Fingerprints;
using Carthago.Services.ProtocolIntelligence;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Carthago.Services
{
    public class PacketHandler
    {
        // Small, best-effort early TCP inspection window; never accumulate full streams.
        private const int MaxInspectBytesPerDir = 4096;
        private const int MaxTrackedFlows = 16384;
        private const int MinUsefulSegment = 8;
        private static readonly TimeSpan FlowIdleTimeout = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan RedisReplyMaxAge = TimeSpan.FromSeconds(30);
        private readonly Dictionary<FlowKey, TcpStreamState> _tcp = new();
        private readonly TftpHandshakeTracker _tftpHandshake = new();
        private readonly object _tcpSync = new();
        private int _flowOperations;
        private readonly Func<DateTime> _utcNow;

        public PacketHandler() : this(() => DateTime.UtcNow) { }

        // Offline capture replay supplies original packet time; live capture retains UTC wall clock.
        internal PacketHandler(Func<DateTime> utcNow) => _utcNow = utcNow ?? throw new ArgumentNullException(nameof(utcNow));

        private sealed class TcpStreamState
        {
            public DirectionState C2S { get; } = new();
            public DirectionState S2C { get; } = new();
            public DateTime LastSeenUtc { get; set; }
            // Exactly one pending Redis CONFIG SET per bounded TCP flow.
            public bool RedisConfigSetPending;
            public DateTime RedisConfigSetRequestedUtc;
            public Smb2WriteExchange.Pending? Smb2Pending;
            public Smb2WriteTargetContext? Smb2Target;
            public Iec104StartupOffSequence? Iec104Startup;
            public OpcUaHelloAckInspector.Hello? OpcUaHello;
            public ModbusOversizedReadExchangeInspector.Pending? ModbusOversizedRead;
            public ModbusBulkFileReadInspector.Pending? ModbusBulkFileRead;
            public FinsNodeNegotiationInspector.Pending? FinsNodeRequest;
            public bool FinsSynAckValid;
            public bool FinsClientSynValid;
        }

        private sealed class DirectionState
        {
            public bool Init;
            // True only after an observed TCP SYN, never on midstream fallback.
            public bool SynAnchored;
            public uint NextSeq;
            public int Collected;
            public bool Invalid;
            public bool TlsActive;
        }

        public TrafficRecord? ParsePacket(PacketCapture e)
        {
            var raw = e.GetPacket();
            return raw?.Data is null
                ? null
                : ParseFrame(raw.Data, raw.LinkLayerType);
        }

        internal TrafficRecord? ParseFrame(byte[] data, LinkLayers linkLayerType)
        {
            try
            {
                if (data.Length == 0)
                    return null;

                ReadOnlySpan<byte> frame = data;

                var link = PortableFrameHeaders.ParseLink(frame, (int)linkLayerType);
                if (link is null) return null;
                string macSrc = link.Value.MacSource;
                string macDst = link.Value.MacDestination;

                // ARP remains separate from IP telemetry.
                if (link.Value.EtherType == 0x0806)
                    return ParseArp(frame, link.Value.Offset, macSrc, macDst);

                var ip = PortableFrameHeaders.ParseIp(frame, link.Value);
                if (ip is null) return null;
                var header = ip.Value;
                bool isIPv4 = header.IsIPv4;
                string srcIp = header.Source, dstIp = header.Destination;
                string ttlStr = header.Ttl, ipVersionStr = header.Version;
                int ipPayloadLen = header.PayloadLength;
                int ipPacketLength = header.PacketLength;
                bool completeIpPacket = header.Complete;

                // ====== L4: shared TCP / UDP / ICMP decoder ======
                var transport = PortableTransportHeaders.Parse(frame, header);
                if (transport is null) return null;
                var l4 = transport.Value;
                int? sport = l4.SourcePort, dport = l4.DestinationPort;
                string protoLabel = l4.Protocol;
                bool isTcp = l4.IsTcp, isUdp = l4.IsUdp;
                ushort? tcpFlagsField = l4.TcpFlags, icmpTypeCode = l4.IcmpTypeCode;
                int? l4PayloadLen = l4.PayloadLength;
                ReadOnlySpan<byte> l4Payload = frame.Slice(l4.PayloadOffset, l4.PayloadCount);
                uint seq = l4.Sequence, ack = l4.Acknowledgment;
                bool tcpSyn = l4.Syn, tcpAck = l4.Ack;

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
                    Length = ipPacketLength,
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

                // ====== TCP flow identity, direction and latency ======
                FlowKey tcpFlow = default;
                bool clientToServer = true;
                if (isTcp)
                {
                    var wireKey = new FlowKey(srcIp, sport ?? 0, dstIp, dport ?? 0, "TCP");
                    (tcpFlow, clientToServer) = ResolveTcpFlow(wireKey, tcpSyn, tcpAck);

                    if (tcpSyn && !tcpAck)
                    {
                        HandshakeBuffer.Remove(tcpFlow);
                        LatencyTracker.NoteSyn(tcpFlow, _utcNow());
                        InitSeq(tcpFlow, clientToServer: true, seqPlus1: unchecked(seq + 1),
                            finsHandshakeEligible: isIPv4 && completeIpPacket && l4Payload.IsEmpty &&
                                tcpFlagsField == 0x02 && dport == 9600 && sport != 9600);
                    }
                    else if (tcpSyn && tcpAck)
                    {
                        LatencyTracker.NoteSynAck(tcpFlow, _utcNow());
                        InitSeq(tcpFlow, clientToServer: false, seqPlus1: unchecked(seq + 1),
                            synAcknowledgment: ack, finsHandshakeEligible: isIPv4 && completeIpPacket &&
                                l4Payload.IsEmpty && tcpFlagsField == 0x12 && sport == 9600 && dport != 9600);
                    }

                    // FIN or RST terminates any pending request, including on
                    // empty-payload segments that skip L7 inspection.
                    if (tcpFlagsField.HasValue && (tcpFlagsField.Value & 0x05) != 0)
                    {
                        lock (_tcpSync)
                            if (_tcp.TryGetValue(tcpFlow, out var flow))
                            {
                                flow.RedisConfigSetPending = false;
                                flow.Smb2Pending = null;
                                flow.Smb2Target = null;
                                flow.Iec104Startup = null;
                                flow.OpcUaHello = null;
                                flow.ModbusOversizedRead = null;
                                flow.ModbusBulkFileRead = null;
                                flow.FinsNodeRequest = null;
                                flow.FinsSynAckValid = false;
                                flow.FinsClientSynValid = false;
                            }
                    }
                }

                // ====== L7 — span-routed, avoid double parse ======
                try
                {
                    if (isTcp)
                    {
                        // Normalize tiny fragments/overlaps for early bytes
                        bool c2s = clientToServer;
                        if (ShouldAcceptSegment(tcpFlow, c2s, seq, l4Payload,
                            out ReadOnlySpan<byte> normPayload, out bool synAnchoredFirstPayload))
                        {
                            // -------- Bounded OT framing --------
                            // Port is a routing hint; ApplicationProtocol is set
                            // only when the captured bytes validate the frame.
                            if (OtProtocolLight.TryIdentifyTcp(normPayload, sport, dport, out var otProtocol))
                                rec.ApplicationProtocol = otProtocol;

                            // Exact IEC104 STARTDT act/con followed by first OFF execution.
                            if (isIPv4 && (c2s ? dport == 2404 && sport != 2404 : sport == 2404 && dport != 2404))
                                ObserveIec104Startup(tcpFlow, rec, c2s, normPayload,
                                    synAnchoredFirstPayload, tcpFlagsField is 0x10 or 0x18 &&
                                    completeIpPacket && normPayload.Length == l4Payload.Length, seq, ack);

                            // OPC UA HEL/ACK on the same observed TCP connection.
                            if (isIPv4 && (c2s ? dport == 4840 && sport != 4840 : sport == 4840 && dport != 4840))
                                ObserveOpcUaHelloAck(tcpFlow, rec, c2s, normPayload,
                                    synAnchoredFirstPayload, tcpFlagsField == 0x18 &&
                                    completeIpPacket && normPayload.Length == l4Payload.Length, seq, ack);

                            // Exact Modbus FC03 oversized read / exception 03 exchange.
                            if (isIPv4 && (c2s ? dport == 502 && sport != 502 : sport == 502 && dport != 502))
                                ObserveModbusOversizedRead(tcpFlow, rec, c2s, normPayload,
                                    synAnchoredFirstPayload, tcpFlagsField == 0x18 &&
                                    completeIpPacket && normPayload.Length == l4Payload.Length, seq, ack);

                            // Exact Modbus FC20 bulk file-record request/response.
                            if (isIPv4 && (c2s ? dport == 502 && sport != 502 : sport == 502 && dport != 502))
                                ObserveModbusBulkFileRead(tcpFlow, rec, c2s, normPayload,
                                    synAnchoredFirstPayload, tcpFlagsField == 0x18 &&
                                    completeIpPacket && normPayload.Length == l4Payload.Length, seq, ack);

                            // Capture-qualified Modbus function 06 first request.
                            // Keep the existing OT protocol label; only internal point evidence is new.
                            if (isIPv4 && c2s && tcpAck && !tcpSyn && synAnchoredFirstPayload &&
                                dport == 502 && sport is > 0 and <= 65535 && sport != 502 &&
                                tcpFlagsField == 0x18 && completeIpPacket &&
                                normPayload.Length == l4Payload.Length && !IsTlsActive(tcpFlow, c2s) &&
                                ModbusSingleRegisterWriteInspector.TryInspect(normPayload, out uint modbusPoint))
                                rec.ModbusSingleRegisterWritePoint = modbusPoint;

                            // Exact FINS/TCP node-address negotiation.
                            if (isIPv4 && (c2s ? dport == 9600 && sport != 9600 : sport == 9600 && dport != 9600))
                                ObserveFinsNodeNegotiation(tcpFlow, rec, c2s, normPayload,
                                    synAnchoredFirstPayload, tcpFlagsField == 0x18 &&
                                    completeIpPacket && normPayload.Length == l4Payload.Length, seq, ack);

                            // Exact FC22 all-zero mask write, first client request only.
                            if (isIPv4 && c2s && tcpAck && !tcpSyn && synAnchoredFirstPayload &&
                                dport == 502 && sport is > 0 and <= 65535 && sport != 502 &&
                                tcpFlagsField == 0x18 && completeIpPacket &&
                                normPayload.Length == l4Payload.Length && !IsTlsActive(tcpFlow, c2s) &&
                                ModbusClearMaskWriteInspector.TryInspect(normPayload))
                                rec.ModbusClearMaskWriteObserved = true;

                            // -------- Plaintext LDAP simple BindRequest --------
                            // Strictly complete first client payload on an
                            // observed SYN-anchored TCP/389 flow, not a port,
                            // LDAP label or a truncated/reassembled guess.
                            // DN and password bytes stay within the span.
                            if (c2s && tcpAck && !tcpSyn && synAnchoredFirstPayload
                                && dport == 389 && sport is > 0 and <= 65535
                                && sport != 389 && !IsTlsActive(tcpFlow, c2s)
                                && completeIpPacket && normPayload.Length == l4Payload.Length
                                && (tcpFlagsField.GetValueOrDefault() & 0x05) == 0
                                && LdapMessageInspector.TryInspectSimpleBind(normPayload,
                                    verifiedPlaintextMessageBoundary: true, out _))
                            {
                                rec.ApplicationProtocol = "ldap.bind.simple";
                                rec.LdapCleartextSimpleBindObserved = true;
                            }

                            // -------- Bounded Redis RESP2 correlation --------
                            // Only a complete first client request immediately
                            // after the observed SYN is admitted. The first server
                            // payload must likewise follow an observed SYN-ACK.
                            // Extra client data, pipelining, gaps or ambiguous replies
                            // invalidate pending state; no command bytes are retained.
                            if (c2s && tcpAck && !tcpSyn
                                && dport == 6379 && sport is > 0 and <= 65535
                                && sport != 6379)
                            {
                                bool admitted = false;
                                if (synAnchoredFirstPayload && !IsTlsActive(tcpFlow, c2s)
                                    && Resp2CommandInspector.TryInspect(normPayload,
                                        verifiedPlaintextClientCommandBoundary: true, out var resp))
                                {
                                    rec.ApplicationProtocol = "redis.resp2";
                                    admitted = resp.IsConfigSetRequest
                                        && resp.BytesConsumed == normPayload.Length;
                                    rec.RedisRespConfigSetRequestObserved = admitted;
                                }

                                // A second client payload before a reply clears
                                // the single outstanding request even if valid.
                                lock (_tcpSync)
                                {
                                    if (_tcp.TryGetValue(tcpFlow, out var flow))
                                    {
                                        flow.RedisConfigSetPending = admitted;
                                        flow.RedisConfigSetRequestedUtc = admitted
                                            ? _utcNow() : default;
                                    }
                                }
                            }
                            else if (!c2s && tcpAck && !tcpSyn
                                && sport == 6379 && dport is > 0 and <= 65535
                                && dport != 6379)
                            {
                                bool pending = false;
                                lock (_tcpSync)
                                {
                                    if (_tcp.TryGetValue(tcpFlow, out var flow))
                                    {
                                        pending = flow.RedisConfigSetPending
                                            && IsWithinRedisReplyWindow(
                                                flow.RedisConfigSetRequestedUtc,
                                                _utcNow());
                                        flow.RedisConfigSetPending = false;
                                        flow.RedisConfigSetRequestedUtc = default;
                                    }
                                }

                                // A wire-correlated RESP +OK is NOT authenticated
                                // server identity, authorized administration or
                                // proof of a completed security-relevant change.
                                if (pending && synAnchoredFirstPayload
                                    && !IsTlsActive(tcpFlow, c2s)
                                    && Resp2SimpleReplyInspector.TryInspect(normPayload,
                                        out var reply))
                                {
                                    rec.ApplicationProtocol = "redis.resp2";
                                    rec.RedisRespConfigSetReplyOkObserved =
                                        reply == Resp2SimpleReplyKind.Ok;
                                    rec.RedisRespConfigSetReplyErrorObserved =
                                        reply == Resp2SimpleReplyKind.Error;
                                }
                            }

                            // -------- Bounded FTP and SMB2 request framing --------
                            if (c2s && NetworkBatch246250Wire.FtpUpload(normPayload, sport, dport, out var ftpOperation))
                                rec.ApplicationProtocol = ftpOperation;
                            if (c2s && NetworkBatch246250Wire.Smb2Write(normPayload, sport, dport))
                                rec.ApplicationProtocol = "smb2.write.request";
                            // Stronger, opt-in evidence for qualified rules. Legacy classification stays intact.
                            if (c2s && tcpAck && !tcpSyn && completeIpPacket
                                && normPayload.Length == l4Payload.Length
                                && (tcpFlagsField.GetValueOrDefault() & 0x05) == 0
                                && !IsTlsActive(tcpFlow, c2s)
                                && Smb2CompleteWriteInspector.TryInspect(normPayload, sport, dport, out var writeLength))
                            {
                                rec.ApplicationProtocol = "smb2.write.request";
                                rec.Smb2CompleteWriteRequestObserved = true;
                                rec.Smb2ValidatedWriteLength = writeLength;
                            }

                            // Corroborating response evidence; attempt predicates remain unchanged.
                            if (sport == 445 || dport == 445)
                                ObserveSmb2WriteExchange(tcpFlow, c2s, rec, normPayload,
                                    tcpAck && !tcpSyn && completeIpPacket
                                    && normPayload.Length == l4Payload.Length
                                    && (tcpFlagsField.GetValueOrDefault() & 0x05) == 0, seq, ack);

                            // -------- Bounded EtherNet/IP ListIdentity and MQTT --------
                            if (NetworkBatch226230Wire.CipListIdentity(normPayload, sport, dport))
                                rec.ApplicationProtocol = "ethernetip.listidentity";
                            if (NetworkBatch226230Wire.Mqtt(normPayload, sport, dport,
                                out var mqttOperation, out var mqttTopic, out var mqttRetain))
                            {
                                rec.ApplicationProtocol = mqttOperation;
                                if (mqttOperation == "mqtt.publish")
                                {
                                    rec.MqttPublishTopicObserved = true;
                                    rec.MqttControlTopicObserved = NetworkBatch226230Wire.IsControlTopic(mqttTopic);
                                    rec.MqttRetain = mqttRetain;
                                }
                                else
                                {
                                    rec.MqttWillTopicObserved = true;
                                    rec.MqttWillControlTopicObserved = NetworkBatch226230Wire.IsControlTopic(mqttTopic);
                                }
                            }

                            // -------- HTTP --------
                            // A complete SYN-anchored RESP2 CONFIG SET response was
                            // already verified above on TCP/6379. The generic HTTP
                            // request-line classifier can mistake RESP error/status
                            // lines for HTTP and overwrite redis.resp2 (including
                            // injecting contradictory HTTP fields). Preserve the
                            // stronger wire-derived protocol attribution instead.
                            // Other traffic, including HTTP on a nonstandard port,
                            // continues through the existing HTTP parser unchanged.
                            if (!string.Equals(rec.ApplicationProtocol, "redis.resp2",
                                    StringComparison.Ordinal)
                                && !rec.LdapCleartextSimpleBindObserved
                                && normPayload.Length >= 4
                                && HttpLight.TryParseHttp(normPayload, out var http))
                            {
                                rec.ApplicationProtocol = "HTTP";
                                rec.HttpMethod = http.Method ?? rec.HttpMethod;
                                rec.HttpUri = http.Path ?? rec.HttpUri;
                                rec.HttpHost = http.Host ?? rec.HttpHost;
                                rec.HttpUserAgent = http.UserAgent ?? rec.HttpUserAgent;
                                rec.HttpRequestHeaders = http.JoinedHeaderLines ?? rec.HttpRequestHeaders;
                                rec.HttpBasicDefaultCredentialObserved = c2s && http.ObservedDefaultBasicCredential;
                                rec.HttpGitHubTokenPatternObserved = c2s && http.ObservedGitHubTokenPattern;
                                rec.HttpGitLabTokenPatternObserved = c2s && http.ObservedGitLabTokenPattern;
                                rec.HttpAzureDevOpsPatUrlObserved = c2s && http.ObservedAzureDevOpsPatUrlPattern;
                                rec.HttpCircleCiTokenPatternObserved = c2s && http.ObservedCircleCiTokenPattern;
                                rec.HttpVaultTokenPatternObserved = c2s && http.ObservedVaultTokenPattern;
                                rec.HttpTerraformTokenPatternObserved = c2s && http.ObservedTerraformTokenPattern;
                                rec.HttpNpmTokenPatternObserved = c2s && http.ObservedNpmTokenPattern;
                                rec.HttpPyPiUploadAuthorizationObserved = c2s && http.ObservedPyPiUploadAuthorization;
                                rec.HttpAwsListSecretsRequestObserved = c2s && http.ObservedAwsListSecretsRequest;

                                var (readable, tag) = HttpJa4H.Compute(http.Method, http.HttpVersion, http.HeaderNames, http.UserAgent);
                                rec.HttpJa4h = $"{readable}|{tag}";

                                if (c2s) LatencyTracker.NoteFirstDataClient(tcpFlow, _utcNow());
                                AppendInfo(rec, $"[HTTP host={rec.HttpHost ?? "-"} ua={(rec.HttpUserAgent ?? "-")}]");
                            }

                            // -------- Bounded RTSP PLAY request line --------
                            if (NetworkBatch231235Wire.RtspPlay(normPayload, sport, dport))
                            {
                                // HttpLight's generic request-line parser may also
                                // accept RTSP. Do not preserve its HTTP classification
                                // or a credential-bearing RTSP URI as HTTP telemetry.
                                rec.ApplicationProtocol = "rtsp.play";
                                rec.HttpMethod = null;
                                rec.HttpUri = null;
                                rec.HttpHost = null;
                                rec.HttpRequestHeaders = null;
                                rec.HttpUserAgent = null;
                                rec.HttpJa4h = null;
                                rec.HttpBasicDefaultCredentialObserved = false;
                                rec.HttpGitHubTokenPatternObserved = false;
                                rec.HttpGitLabTokenPatternObserved = false;
                                rec.HttpAzureDevOpsPatUrlObserved = false;
                                rec.HttpCircleCiTokenPatternObserved = false;
                            }

                            // -------- DNS over TCP (length-prefixed DNS message) --------
                            if ((sport == 53 || dport == 53) &&
                                DnsLight.TryParse(normPayload, isTcp: true, out var dnsTcp))
                            {
                                rec.ApplicationService = "DNS";
                                rec.ApplicationProtocol = "DNS";
                                rec.DnsQname = dnsTcp.QName;
                                rec.DnsQtype = dnsTcp.QType;
                                rec.DnsRcode = dnsTcp.Rcode;
                                rec.DnsIsResponse = dnsTcp.IsResponse;
                            }

                            // -------- TLS -------- (client/server hello + certificate)
                            bool tlsStart = normPayload.Length > 0 && normPayload[0] == 0x16;
                            if (tlsStart) MarkTlsActive(tcpFlow, c2s);
                            if (tlsStart || IsTlsActive(tcpFlow, c2s))
                            {
                                if (c2s)
                                {
                                    HandshakeBuffer.AddClientBytes(tcpFlow, normPayload);
                                    var ch = HandshakeBuffer.TryGetClientHello(tcpFlow);
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
                                    HandshakeBuffer.AddServerBytes(tcpFlow, normPayload);
                                    HandshakeBuffer.TryGetServerHellos(tcpFlow, out var sh, out var cert);
                                    if (!sh.IsEmpty)
                                    {
                                        rec.TlsJa4s = TlsJa4.FromServerHello(sh);
                                        if (TlsIdentityEnrichment.TryReadServerHello(sh, out var negotiated))
                                        {
                                            rec.TlsObservedNegotiatedVersion = negotiated.Version;
                                            rec.TlsObservedNegotiatedAlpn = negotiated.Alpn;
                                        }
                                    }

                                    if (!cert.IsEmpty)
                                    {
                                        TryExtractCert(rec, cert);
                                        LatencyTracker.NoteFirstDataServer(tcpFlow, _utcNow());
                                    }

                                    var (l, ls) = LatencyTracker.GetLatencyFingerprints(tcpFlow);
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

                                string? kex = null, enc = null, mac = null;
                                if (banner != null)
                                    rec.SshJa4 = SshJa4SSH.From(banner, kex, enc, mac);
                                // HASSH requires real KEXINIT algorithms; do not invent them.
                            }
                        }
                    }
                    else if (isUdp)
                    {
                        // -------- Bounded OT framing --------
                        if (OtProtocolLight.TryIdentifyUdp(l4Payload, sport, dport, out var otProtocol))
                            rec.ApplicationProtocol = otProtocol;

                        // -------- BACnet WriteProperty confirmed request --------
                        // One complete BACnet/IP UDP request, destination 47808.
                        // Never claim an accepted/authorized property change.
                        if (isIPv4 && dport == 47808 && sport is > 0 and <= 65535
                            && completeIpPacket
                            && l4PayloadLen == ipPayloadLen - 8
                            && BacnetWritePropertyInspector.TryInspect(l4Payload,
                                verifiedCompletePlaintextUdpDatagram: true, out _))
                        {
                            rec.ApplicationProtocol = "bacnet.writeproperty.request";
                            rec.BacnetWritePropertyRequestObserved = true;
                        }

                        // -------- BACnet DeviceCommunicationControl disable --------
                        // A real, unsegmented request can originate on the same
                        // UDP service port. No controller outcome or password is
                        // inferred or retained by this capture-only signal.
                        if (isIPv4 && dport == 47808 && sport is > 0 and <= 65535
                            && completeIpPacket
                            && l4PayloadLen == ipPayloadLen - 8
                            && BacnetDeviceCommunicationControlInspector.TryInspect(
                                l4Payload, verifiedCompletePlaintextUdpDatagram: true, out _))
                        {
                            rec.ApplicationProtocol = "bacnet.devicecommunicationcontrol.disable";
                            rec.BacnetDeviceCommunicationDisableObserved = true;
                        }

                        // Exact BACnet/IP coldstart/warmstart confirmed request.
                        if (isIPv4 && dport == 47808 && sport is > 0 and <= 65535 &&
                            completeIpPacket && l4PayloadLen == ipPayloadLen - 8 && !rec.IsQuic &&
                            BacnetReinitializeDeviceInspector.TryInspect(l4Payload))
                        {
                            rec.ApplicationProtocol = "bacnet.reinitialize_device.request";
                            rec.BacnetReinitializeDeviceRequestObserved = true;
                        }

                        // Exact BACnet Device Object_List whole-array read.
                        if (isIPv4 && dport == 47808 && sport is > 0 and <= 65535 &&
                            completeIpPacket && l4PayloadLen == ipPayloadLen - 8 && !rec.IsQuic &&
                            BacnetObjectListReadInspector.TryInspect(l4Payload))
                        {
                            rec.ApplicationProtocol = "bacnet.device.object_list.read";
                            rec.BacnetObjectListReadObserved = true;
                        }

                        // Exact BACnet Event_Enable all-transition disable bit string.
                        if (isIPv4 && dport == 47808 && sport is > 0 and <= 65535 &&
                            completeIpPacket && l4PayloadLen == ipPayloadLen - 8 && !rec.IsQuic &&
                            BacnetEventDisableInspector.TryInspect(l4Payload))
                        {
                            rec.ApplicationProtocol = "bacnet.event_enable.disable_all.request";
                            rec.BacnetEventDisableRequestObserved = true;
                        }

                        // -------- Bounded CoAP and WS-Discovery requests --------
                        if (NetworkBatch231235Wire.CoapDiscovery(l4Payload, sport, dport))
                            rec.ApplicationProtocol = "coap.discovery";
                        if (NetworkBatch231235Wire.WsDiscoveryProbe(l4Payload, sport, dport))
                            rec.ApplicationProtocol = "onvif.wsdiscovery.probe";
                        if ((sport == 5353 || dport == 5353) &&
                            DnsLight.TryParse(l4Payload, isTcp: false, out var mdns))
                        {
                            rec.ApplicationProtocol = "mDNS";
                            rec.DnsQname = mdns.QName;
                            rec.DnsQtype = mdns.QType;
                            rec.DnsRcode = mdns.Rcode;
                            rec.DnsIsResponse = mdns.IsResponse;
                        }

                        // Enrichment-only DNS evidence, separate from the strict
                        // single-A detection qualification contract below.
                        if (completeIpPacket && l4PayloadLen == ipPayloadLen - 8
                            && (sport == 53 || dport == 53)
                            && DnsAddressObservationInspector.TryInspect(l4Payload, out var addressDns)
                            && (addressDns!.IsResponse ? sport == 53 : dport == 53))
                            rec.DnsAddressObservation = addressDns;

                        // -------- Complete standard UDP DNS IN/A observation --------
                        if (isIPv4 && completeIpPacket && l4PayloadLen == ipPayloadLen - 8
                            && (sport == 53 || dport == 53)
                            && DnsAObservationInspector.TryInspect(l4Payload, out var observedDns)
                            && (observedDns.IsResponse ? sport == 53 : dport == 53))
                        {
                            rec.ApplicationService = "DNS";
                            rec.ApplicationProtocol = "DNS";
                            rec.DnsValidatedTransactionId = observedDns.TransactionId;
                            rec.DnsValidatedAQuestion = true;
                            rec.DnsValidatedQuestionName = observedDns.Name;
                            rec.DnsValidatedSingleAAnswer = observedDns.Address != null;
                            rec.DnsValidatedNxdomain = observedDns.IsNxdomain;
                            rec.DnsValidatedAnswerAddress = observedDns.Address;
                            rec.DnsValidatedAnswerTtl = observedDns.Ttl;
                            rec.DnsQname = observedDns.Name;
                            rec.DnsQtype = "A";
                            rec.DnsRcode = observedDns.IsNxdomain ? "NXDOMAIN" : "NOERROR";
                            rec.DnsIsResponse = observedDns.IsResponse;
                            rec.DnsAnswers = observedDns.Address;
                            rec.DnsTtl = observedDns.Ttl;
                        }

                        // -------- QUIC --------
                        if (!rec.DnsValidatedAQuestion && l4Payload.Length >= 6 && QuicLight.TryDetectQuic(l4Payload, out var quic))
                        {
                            rec.ApplicationProtocol = "QUIC";
                            rec.IsQuic = true;
                            rec.QuicVersion = quic.VersionLabel ?? rec.QuicVersion;
                            AppendInfo(rec, $"[QUIC v={rec.QuicVersion ?? "-"}]");
                        }

                        // -------- DNS (UDP or TCP path compatible) --------
                        if (!rec.DnsValidatedAQuestion && (rec.DestinationPort == 53 || rec.SourcePort == 53) &&
                            DnsLight.TryParse(l4Payload, isTcp: false, out var dns))
                        {
                            rec.ApplicationService = "DNS";
                            rec.DnsQname = dns.QName ?? rec.DnsQname;
                            rec.DnsQtype = dns.QType ?? rec.DnsQtype;
                            rec.DnsRcode = dns.Rcode ?? rec.DnsRcode;
                            rec.DnsIsResponse = dns.IsResponse;
                            AppendInfo(rec, $"[DNS {(dns.IsResponse ? "ans" : "q")}={rec.DnsQname ?? "-"} {rec.DnsQtype ?? "?"}]");
                        }

                        // Complete, capture-attested SNMP enterprise SET. No community or value retained.
                        if (isIPv4 && dport == 161 && sport is > 0 and <= 65535 &&
                            completeIpPacket && l4PayloadLen == ipPayloadLen - 8 && !rec.IsQuic)
                        {
                            if (SnmpEnterpriseSetInspector.TryInspect(l4Payload))
                            {
                                rec.ApplicationProtocol = "snmp.enterprise.set.request";
                                rec.SnmpEnterpriseSetRequestObserved = true;
                            }
                            else if (SnmpEnterpriseSetInspector.TryInspectUpsReboot(l4Payload))
                            {
                                rec.ApplicationProtocol = "snmp.ups.reboot.request";
                                rec.SnmpUpsRebootRequestObserved = true;
                            }
                            else if (sport != 161 && SnmpEnterpriseSetInspector.TryInspectHighDemandBulk(l4Payload))
                            {
                                rec.ApplicationProtocol = "snmp.getbulk.high_demand.request";
                                rec.SnmpHighDemandGetBulkObserved = true;
                            }
                            else if (sport != 161 && SnmpEnterpriseSetInspector.TryInspectSystemFingerprintGet(l4Payload))
                            {
                                rec.ApplicationProtocol = "snmp.get.system_fingerprint.request";
                                rec.SnmpSystemFingerprintGetObserved = true;
                            }
                            else if (sport != 161 && SnmpEnterpriseSetInspector.TryInspectConnectionTableGetNext(l4Payload))
                            {
                                rec.ApplicationProtocol = "snmp.getnext.connection_tables.request";
                                rec.SnmpConnectionTableGetNextObserved = true;
                            }
                        }

                        // Complete DNP3 unsolicited binary input events. CRC is not authentication.
                        if (isIPv4 && sport == 20000 && dport == 20000 &&
                            completeIpPacket && l4PayloadLen == ipPayloadLen - 8 && !rec.IsQuic &&
                            Dnp3UnsolicitedBinaryEventInspector.TryInspect(l4Payload))
                        {
                            rec.ApplicationProtocol = "dnp3.unsolicited.binary_event";
                            rec.Dnp3UnsolicitedBinaryEventObserved = true;
                        }

                        // Exact master-to-outstation DNP3 cold/warm restart request.
                        if (isIPv4 && sport == 20000 && dport == 20000 &&
                            completeIpPacket && l4PayloadLen == ipPayloadLen - 8 && !rec.IsQuic &&
                            Dnp3RestartRequestInspector.TryInspect(l4Payload))
                        {
                            rec.ApplicationProtocol = "dnp3.restart.request";
                            rec.Dnp3RestartRequestObserved = true;
                        }

                        // Exact DNP3 disable unsolicited for all three event classes.
                        if (isIPv4 && sport == 20000 && dport == 20000 &&
                            completeIpPacket && l4PayloadLen == ipPayloadLen - 8 && !rec.IsQuic &&
                            Dnp3DisableUnsolicitedInspector.TryInspect(l4Payload))
                        {
                            rec.ApplicationProtocol = "dnp3.disable_unsolicited.request";
                            rec.Dnp3DisableUnsolicitedObserved = true;
                        }

                        // Capture-attested TFTP initial request/first reply, not generic port guessing.
                        if (isIPv4 && completeIpPacket && l4PayloadLen == ipPayloadLen - 8)
                            _tftpHandshake.Observe(rec, l4Payload, true, _utcNow());
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[PacketHandler] L7 parse error: {ex.Message}");
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

        private static void TryExtractCert(TrafficRecord rec, ReadOnlySpan<byte> certMsg)
        {
            // TLS record header (5) + handshake header (4)
            if (certMsg.Length < 9) return;
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
                using var x = new X509Certificate2(der);
                rec.CertIssuer = x.Issuer;
                rec.CertSubject = x.Subject;
                rec.CertValidFrom = x.NotBefore.ToUniversalTime();
                rec.CertValidTo = x.NotAfter.ToUniversalTime();
                // Rich identity is captured separately from legacy rule fields.
                if (hsLen == body.Length && certLen > 0
                    && ((body[0] << 16) | (body[1] << 8) | body[2]) == body.Length - 3)
                    TlsIdentityEnrichment.ApplyCertificate(rec, x);
            }
            catch { /* ignore */ }
        }

        // SYN establishes the canonical client->server key. When capturing midstream,
        // use the previously observed 5-tuple before falling back to port heuristics.
        private (FlowKey Key, bool ClientToServer) ResolveTcpFlow(FlowKey wire, bool syn, bool ack)
        {
            if (syn && !ack) return (wire, true);
            if (syn && ack) return (wire.Reverse(), false);

            lock (_tcpSync)
            {
                if (_tcp.ContainsKey(wire)) return (wire, true);
                var reverse = wire.Reverse();
                if (_tcp.ContainsKey(reverse)) return (reverse, false);
            }

            // Source ephemeral port normally exceeds destination service port.
            // This is only a fallback: nonstandard services can be ambiguous.
            bool c2s = wire.SrcPort >= wire.DstPort;
            return c2s ? (wire, true) : (wire.Reverse(), false);
        }

        private TcpStreamState GetOrAddState(FlowKey key, DateTime nowUtc)
        {
            // Caller must hold _tcpSync.
            if (++_flowOperations % 1024 == 0 || _tcp.Count >= MaxTrackedFlows)
            {
                var expired = new List<FlowKey>();
                foreach (var item in _tcp)
                    if (nowUtc - item.Value.LastSeenUtc > FlowIdleTimeout)
                        expired.Add(item.Key);
                foreach (var oldKey in expired) _tcp.Remove(oldKey);
            }

            if (!_tcp.TryGetValue(key, out var state))
            {
                if (_tcp.Count >= MaxTrackedFlows)
                {
                    // Evict oldest state under sustained cardinality pressure.
                    FlowKey oldestKey = default;
                    DateTime oldest = DateTime.MaxValue;
                    foreach (var item in _tcp)
                    {
                        if (item.Value.LastSeenUtc < oldest)
                        {
                            oldest = item.Value.LastSeenUtc;
                            oldestKey = item.Key;
                        }
                    }
                    _tcp.Remove(oldestKey);
                }
                state = new TcpStreamState();
                _tcp[key] = state;
            }
            state.LastSeenUtc = nowUtc;
            return state;
        }

        private void InitSeq(FlowKey key, bool clientToServer, uint seqPlus1,
            uint synAcknowledgment = 0, bool finsHandshakeEligible = false)
        {
            lock (_tcpSync)
            {
                var state = GetOrAddState(key, _utcNow());
                // FINS negotiation requires the original complete client SYN
                // and a matching server SYN-ACK, without changing other rules.
                if (clientToServer)
                {
                    state.FinsClientSynValid = finsHandshakeEligible;
                    state.FinsSynAckValid = false;
                }
                else
                    state.FinsSynAckValid = finsHandshakeEligible && state.FinsClientSynValid &&
                        state.C2S.SynAnchored && state.C2S.Collected == 0 &&
                        !state.C2S.Invalid && state.C2S.NextSeq == synAcknowledgment;
                // A new client SYN invalidates both directions of a reused
                // 5-tuple, so an old SYN-ACK cannot authenticate this flow.
                if (clientToServer)
                {
                    state.S2C.Init = false;
                    state.S2C.SynAnchored = false;
                    state.S2C.NextSeq = 0;
                    state.S2C.Collected = 0;
                    state.S2C.Invalid = false;
                    state.S2C.TlsActive = false;
                }
                var dir = clientToServer ? state.C2S : state.S2C;
                dir.Init = true;
                dir.SynAnchored = true;
                dir.NextSeq = seqPlus1;
                dir.Collected = 0;
                dir.Invalid = false;
                dir.TlsActive = false;
                state.RedisConfigSetPending = false;
                state.RedisConfigSetRequestedUtc = default;
                state.Smb2Pending = null;
                state.Smb2Target = null;
                state.Iec104Startup = null;
                state.OpcUaHello = null;
                state.ModbusOversizedRead = null;
                state.ModbusBulkFileRead = null;
                state.FinsNodeRequest = null;
            }
        }

        private void MarkTlsActive(FlowKey key, bool clientToServer)
        {
            lock (_tcpSync)
            {
                if (_tcp.TryGetValue(key, out var state))
                {
                    (clientToServer ? state.C2S : state.S2C).TlsActive = true;
                    state.Smb2Pending = null;
                    state.Smb2Target = null;
                    state.Iec104Startup = null;
                    state.OpcUaHello = null;
                    state.ModbusOversizedRead = null;
                    state.ModbusBulkFileRead = null;
                    state.FinsNodeRequest = null;
                }
            }
        }

        private bool IsTlsActive(FlowKey key, bool clientToServer)
        {
            lock (_tcpSync)
            {
                return _tcp.TryGetValue(key, out var state) &&
                    (clientToServer ? state.C2S : state.S2C).TlsActive;
            }
        }

        // Strictly bounded UTC request/reply age check without scheduled timers,
        // retained wire payloads or background workers.
        internal static bool IsWithinRedisReplyWindow(DateTime requestUtc, DateTime replyUtc)
            => requestUtc.Kind == DateTimeKind.Utc
                && replyUtc.Kind == DateTimeKind.Utc
                && replyUtc >= requestUtc
                && replyUtc - requestUtc <= RedisReplyMaxAge;

        private void ObserveIec104Startup(FlowKey key, TrafficRecord record, bool client,
            ReadOnlySpan<byte> data, bool first, bool complete, uint seq, uint ack)
        {
            lock (_tcpSync)
            {
                if (!_tcp.TryGetValue(key, out var flow)) return;
                var dir = client ? flow.C2S : flow.S2C;
                var opposite = client ? flow.S2C : flow.C2S;
                if (!complete || !dir.SynAnchored || !opposite.SynAnchored ||
                    dir.Invalid || opposite.Invalid || dir.TlsActive || opposite.TlsActive ||
                    dir.NextSeq != unchecked(seq + (uint)data.Length) || ack != opposite.NextSeq)
                { flow.Iec104Startup = null; return; }

                if (flow.Iec104Startup == null && client && first && data.Length == 6)
                    flow.Iec104Startup = new Iec104StartupOffSequence();
                if (flow.Iec104Startup != null &&
                    flow.Iec104Startup.Observe(data, client, first, true, _utcNow()))
                {
                    record.Iec104StartupOffExecuteObserved = true;
                    flow.Iec104Startup = null;
                }
            }
        }

        private void ObserveOpcUaHelloAck(FlowKey key, TrafficRecord record, bool client,
            ReadOnlySpan<byte> data, bool first, bool complete, uint seq, uint ack)
        {
            lock (_tcpSync)
            {
                if (!_tcp.TryGetValue(key, out var flow)) return;
                var pending = flow.OpcUaHello;
                flow.OpcUaHello = null;
                var dir = client ? flow.C2S : flow.S2C;
                var opposite = client ? flow.S2C : flow.C2S;
                if (!first || !complete || !dir.SynAnchored || !opposite.SynAnchored ||
                    dir.Invalid || opposite.Invalid || dir.TlsActive || opposite.TlsActive ||
                    dir.NextSeq != unchecked(seq + (uint)data.Length) || ack != opposite.NextSeq)
                    return;
                var now = _utcNow();
                if (client)
                {
                    if (OpcUaHelloAckInspector.TryHello(data, now, out var hello))
                        flow.OpcUaHello = hello;
                }
                else if (pending.HasValue && OpcUaHelloAckInspector.IsMatchingAck(data, pending.Value, now))
                    record.OpcUaHelloAckObserved = true;
            }
        }

        private void ObserveModbusOversizedRead(FlowKey key, TrafficRecord record, bool client,
            ReadOnlySpan<byte> data, bool first, bool complete, uint seq, uint ack)
        {
            lock (_tcpSync)
            {
                if (!_tcp.TryGetValue(key, out var flow)) return;
                var pending = flow.ModbusOversizedRead;
                flow.ModbusOversizedRead = null;
                var dir = client ? flow.C2S : flow.S2C;
                var opposite = client ? flow.S2C : flow.C2S;
                if (!first || !complete || !dir.SynAnchored || !opposite.SynAnchored ||
                    dir.Invalid || opposite.Invalid || dir.TlsActive || opposite.TlsActive ||
                    dir.NextSeq != unchecked(seq + (uint)data.Length) || ack != opposite.NextSeq)
                    return;
                var now = _utcNow();
                if (client)
                {
                    if (ModbusOversizedReadExchangeInspector.TryRequest(data, now, out var request))
                        flow.ModbusOversizedRead = request;
                }
                else if (pending.HasValue &&
                    ModbusOversizedReadExchangeInspector.IsMatchingException(data, pending.Value, now))
                    record.ModbusOversizedReadExceptionObserved = true;
            }
        }

        private void ObserveModbusBulkFileRead(FlowKey key, TrafficRecord record, bool client,
            ReadOnlySpan<byte> data, bool first, bool complete, uint seq, uint ack)
        {
            lock (_tcpSync)
            {
                if (!_tcp.TryGetValue(key, out var flow)) return;
                var pending = flow.ModbusBulkFileRead;
                flow.ModbusBulkFileRead = null;
                var dir = client ? flow.C2S : flow.S2C;
                var opposite = client ? flow.S2C : flow.C2S;
                if (!first || !complete || !dir.SynAnchored || !opposite.SynAnchored ||
                    dir.Invalid || opposite.Invalid || dir.TlsActive || opposite.TlsActive ||
                    dir.NextSeq != unchecked(seq + (uint)data.Length) || ack != opposite.NextSeq)
                    return;
                var now = _utcNow();
                if (client)
                {
                    if (ModbusBulkFileReadInspector.TryRequest(data, now, out var request))
                        flow.ModbusBulkFileRead = request;
                }
                else if (pending.HasValue &&
                    ModbusBulkFileReadInspector.IsMatchingResponse(data, pending.Value, now))
                    record.ModbusBulkFileReadResponseObserved = true;
            }
        }

        private void ObserveFinsNodeNegotiation(FlowKey key, TrafficRecord record, bool client,
            ReadOnlySpan<byte> data, bool first, bool complete, uint seq, uint ack)
        {
            lock (_tcpSync)
            {
                if (!_tcp.TryGetValue(key, out var flow)) return;
                var pending = flow.FinsNodeRequest;
                flow.FinsNodeRequest = null;
                var dir = client ? flow.C2S : flow.S2C;
                var opposite = client ? flow.S2C : flow.C2S;
                if (!flow.FinsSynAckValid || !first || !complete ||
                    !dir.SynAnchored || !opposite.SynAnchored ||
                    dir.Invalid || opposite.Invalid || dir.TlsActive || opposite.TlsActive ||
                    dir.NextSeq != unchecked(seq + (uint)data.Length) || ack != opposite.NextSeq)
                    return;
                var now = _utcNow();
                if (client)
                {
                    if (FinsNodeNegotiationInspector.TryRequest(data, now, out var request))
                        flow.FinsNodeRequest = request;
                }
                else if (pending.HasValue &&
                    FinsNodeNegotiationInspector.IsMatchingResponse(data, pending.Value, now))
                {
                    record.ApplicationProtocol = "fins.tcp.node_negotiation.response";
                    record.FinsNodeNegotiationObserved = true;
                }
            }
        }

        // One outstanding request per existing bounded TCP flow. No raw payload retained.
        private void ObserveSmb2WriteExchange(FlowKey key, bool c2s, TrafficRecord record,
            ReadOnlySpan<byte> payload, bool complete, uint seq, uint ack)
        {
            lock (_tcpSync)
            {
                if (!_tcp.TryGetValue(key, out var flow)) return;
                var pending = flow.Smb2Pending;
                flow.Smb2Pending = null;
                var direction = c2s ? flow.C2S : flow.S2C;
                if (!complete || !flow.C2S.SynAnchored || !flow.S2C.SynAnchored
                    || flow.C2S.Invalid || flow.S2C.Invalid || flow.C2S.TlsActive || flow.S2C.TlsActive
                    || direction.NextSeq != unchecked(seq + (uint)payload.Length))
                {
                    flow.Smb2Target = null;
                    return;
                }
                var now = _utcNow();
                // Separate one-shot context; Q5 WRITE correlation remains independent.
                if ((c2s && record.DestinationPort == 445 && record.SourcePort == key.SrcPort)
                    || (!c2s && record.SourcePort == 445 && record.DestinationPort == key.SrcPort))
                {
                    if (flow.Smb2Target == null && c2s && Smb2WriteTargetContext.IsTreeRequest(payload))
                        flow.Smb2Target = new Smb2WriteTargetContext();
                    if (flow.Smb2Target != null
                        && !flow.Smb2Target.Observe(record, payload, c2s, direction.NextSeq, ack, now))
                        flow.Smb2Target = null;
                }
                else flow.Smb2Target = null;
                if (c2s)
                {
                    // Pipelined writes are deliberately not correlated in this subset.
                    if (pending.HasValue || !record.Smb2CompleteWriteRequestObserved
                        || record.Smb2ValidatedWriteLength is not uint length || record.Id == Guid.Empty) return;
                    flow.Smb2Pending = Smb2WriteExchange.FromValidatedRequest(
                        payload, length, record.Id, direction.NextSeq, now);
                    return;
                }
                if (!pending.HasValue || record.SourcePort != 445 || record.DestinationPort != key.SrcPort
                    || !Smb2WriteExchange.TryMatchReply(payload, pending.Value, ack, now,
                        out uint status, out uint? count)) return;
                record.Smb2WriteResponseCorrelationId = pending.Value.RequestId;
                record.Smb2WriteResponseStatus = status;
                record.Smb2WriteAcknowledgedLength = count;
                record.ApplicationProtocol = "smb2.write.response";
            }
        }

        private bool ShouldAcceptSegment(FlowKey key, bool clientToServer, uint seq,
            ReadOnlySpan<byte> payload, out ReadOnlySpan<byte> normalized,
            out bool synAnchoredFirstPayload)
        {
            normalized = ReadOnlySpan<byte>.Empty;
            synAnchoredFirstPayload = false;
            if (payload.IsEmpty) return false;

            lock (_tcpSync)
            {
                var state = GetOrAddState(key, _utcNow());
                var dir = clientToServer ? state.C2S : state.S2C;
                if (dir.Invalid || dir.Collected >= MaxInspectBytesPerDir)
                {
                    state.RedisConfigSetPending = false;
                    state.Smb2Pending = null;
                    state.Smb2Target = null;
                        state.Iec104Startup = null;
                        state.OpcUaHello = null;
                        state.ModbusOversizedRead = null;
                        state.ModbusBulkFileRead = null;
                        state.FinsNodeRequest = null;
                    return false;
                }

                // Checked under the flow lock before changing sequence state.
                // Both client and server first-payload boundaries must be
                // SYN-anchored and TCP-sequence-contiguous.
                synAnchoredFirstPayload = dir.Init && dir.SynAnchored
                    && dir.Collected == 0 && dir.NextSeq == seq;
                int overlap = 0;
                if (!dir.Init)
                {
                    if (payload.Length < MinUsefulSegment && !LooksLikeHandshakePrefix(payload))
                        return false;
                    dir.Init = true;
                }
                else
                {
                    // Signed subtraction handles normal uint TCP sequence wraparound.
                    int diff = unchecked((int)(seq - dir.NextSeq));
                    if (diff > 0)
                    {
                        dir.Invalid = true;
                        state.RedisConfigSetPending = false;
                        state.Smb2Pending = null;
                        state.Smb2Target = null;
                        state.Iec104Startup = null;
                        state.OpcUaHello = null;
                        state.ModbusOversizedRead = null;
                        state.ModbusBulkFileRead = null;
                        state.FinsNodeRequest = null;
                        return false; // missing segment
                    }
                    if (diff < 0)
                    {
                        long overlap64 = -(long)diff;
                        if (overlap64 >= payload.Length)
                        {
                            state.RedisConfigSetPending = false;
                            state.Smb2Pending = null;
                            state.Smb2Target = null;
                        state.Iec104Startup = null;
                        state.OpcUaHello = null;
                        state.ModbusOversizedRead = null;
                        state.ModbusBulkFileRead = null;
                        state.FinsNodeRequest = null;
                            return false; // retransmission while pending: fail closed
                        }
                        if (overlap64 > 3)
                        {
                            dir.Invalid = true;
                            state.RedisConfigSetPending = false;
                            state.Smb2Pending = null;
                            state.Smb2Target = null;
                        state.Iec104Startup = null;
                        state.OpcUaHello = null;
                        state.ModbusOversizedRead = null;
                        state.ModbusBulkFileRead = null;
                        state.FinsNodeRequest = null;
                            return false;
                        }
                        overlap = (int)overlap64;
                    }
                }

                // Advance wire sequence by all new bytes, but inspect at most 4 KiB.
                int newBytes = payload.Length - overlap;
                dir.NextSeq = unchecked(seq + (uint)payload.Length);
                int inspect = Math.Min(newBytes, MaxInspectBytesPerDir - dir.Collected);
                dir.Collected += inspect;
                normalized = payload.Slice(overlap, inspect);
                return inspect > 0;
            }
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

        private static TrafficRecord? ParseArp(
            ReadOnlySpan<byte> frame, int offset, string ethernetSource, string ethernetDestination)
        {
            const int arpLength = 28;
            if (offset < 0 || frame.Length - offset < arpLength)
                return null;

            var arp = frame.Slice(offset, arpLength);
            if (BinaryPrimitives.ReadUInt16BigEndian(arp.Slice(0, 2)) != 1 || // Ethernet
                BinaryPrimitives.ReadUInt16BigEndian(arp.Slice(2, 2)) != 0x0800 || // IPv4
                arp[4] != 6 || arp[5] != 4)
                return null;

            var operation = BinaryPrimitives.ReadUInt16BigEndian(arp.Slice(6, 2));
            if (operation is not 1 and not 2)
                return null;

            var source = new IPAddress(arp.Slice(14, 4)).ToString();
            var destination = new IPAddress(arp.Slice(24, 4)).ToString();
            var senderMac = MacToString(arp.Slice(8, 6));
            var info = operation == 1
                ? $"Who has {destination}? Tell {source}"
                : $"{source} is at {senderMac}";

            return new TrafficRecord
            {
                Timestamp = DateTime.Now.ToString("HH:mm:ss"),
                Source = source,
                Destination = destination,
                Protocol = "ARP",
                ArpSenderMacMatchesFrame = string.Equals(senderMac, ethernetSource, StringComparison.OrdinalIgnoreCase),
                ProtocolVersion = "ARP/IPv4",
                Length = frame.Length,
                Info = info,
                Checksum = "N/A",
                MacSource = string.IsNullOrEmpty(senderMac) ? ethernetSource : senderMac,
                MacDestination = ethernetDestination,
                IsTcp = false,
                IsUdp = false,
                IpVersion = null,
                ApplicationProtocol = "ARP",
                IsVpn = null,
                IsProxy = null
            };
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

        private static string MacToString(ReadOnlySpan<byte> mac) => PortableFrameHeaders.MacToString(mac);

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
