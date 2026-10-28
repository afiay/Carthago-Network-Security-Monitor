// SPDX-License-Identifier: MIT
// File: Models/TrafficRecord.cs

using System;
using System.ComponentModel;

namespace Carthago.Models
{
    public class TrafficRecord : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        // ===== Core =====
        private Guid _id = Guid.NewGuid();
        public Guid Id { get => _id; set { _id = value; OnChanged(nameof(Id)); } }

        private string? _timestamp;
        public string? Timestamp { get => _timestamp; set { _timestamp = value; OnChanged(nameof(Timestamp)); } }

        private string? _source;
        public string? Source { get => _source; set { _source = value; OnChanged(nameof(Source)); } }

        private string? _destination;
        public string? Destination { get => _destination; set { _destination = value; OnChanged(nameof(Destination)); } }

        private string? _protocol;
        public string? Protocol { get => _protocol; set { _protocol = value; OnChanged(nameof(Protocol)); } }

        private int _length;
        public int Length { get => _length; set { _length = value; OnChanged(nameof(Length)); } }

        private string? _info;
        public string? Info { get => _info; set { _info = value; OnChanged(nameof(Info)); } }

        private int? _sourcePort;
        public int? SourcePort { get => _sourcePort; set { _sourcePort = value; OnChanged(nameof(SourcePort)); } }

        private int? _destinationPort;
        public int? DestinationPort { get => _destinationPort; set { _destinationPort = value; OnChanged(nameof(DestinationPort)); } }

        private string? _protocolVersion;
        public string? ProtocolVersion { get => _protocolVersion; set { _protocolVersion = value; OnChanged(nameof(ProtocolVersion)); } }

        private string? _flags;
        public string? Flags { get => _flags; set { _flags = value; OnChanged(nameof(Flags)); } }

        private string? _ttl;
        public string? TTL { get => _ttl; set { _ttl = value; OnChanged(nameof(TTL)); } }

        private string? _checksum;
        public string? Checksum { get => _checksum; set { _checksum = value; OnChanged(nameof(Checksum)); } }

        private string? _macSource;
        public string? MacSource { get => _macSource; set { _macSource = value; OnChanged(nameof(MacSource)); } }

        private string? _macDestination;
        public string? MacDestination { get => _macDestination; set { _macDestination = value; OnChanged(nameof(MacDestination)); } }

        private bool _isTcp;
        public bool IsTcp { get => _isTcp; set { _isTcp = value; OnChanged(nameof(IsTcp)); } }

        private bool _isUdp;
        public bool IsUdp { get => _isUdp; set { _isUdp = value; OnChanged(nameof(IsUdp)); } }

        // ===== Header-only summary fields (fast path) =====
        private int? _ipVersion;                // 4 or 6
        public int? IpVersion { get => _ipVersion; set { _ipVersion = value; OnChanged(nameof(IpVersion)); } }

        private ushort? _tcpFlags;              // raw flags incl. NS bit (if available)
        public ushort? TcpFlags { get => _tcpFlags; set { _tcpFlags = value; OnChanged(nameof(TcpFlags)); } }

        private ushort? _icmpTypeCode;          // (type<<8 | code)
        public ushort? IcmpTypeCode { get => _icmpTypeCode; set { _icmpTypeCode = value; OnChanged(nameof(IcmpTypeCode)); } }

        private int? _l4Len;                    // transport payload length (TCP data or UDP payload)
        public int? L4Len { get => _l4Len; set { _l4Len = value; OnChanged(nameof(L4Len)); } }

        // ===== L7 identification =====
        private string? _applicationProtocol;
        public string? ApplicationProtocol { get => _applicationProtocol; set { _applicationProtocol = value; OnChanged(nameof(ApplicationProtocol)); } }

        private string? _applicationService;
        public string? ApplicationService { get => _applicationService; set { _applicationService = value; OnChanged(nameof(ApplicationService)); } }

        // ===== Process / host enrichment =====
        private string? _processName;
        public string? ProcessName { get => _processName; set { _processName = value; OnChanged(nameof(ProcessName)); } }

        private int _processId;
        public int ProcessId { get => _processId; set { _processId = value; OnChanged(nameof(ProcessId)); } }

        private string? _networkType;
        public string? NetworkType { get => _networkType; set { _networkType = value; OnChanged(nameof(NetworkType)); } }

        private bool? _isVpn;
        public bool? IsVpn { get => _isVpn; set { _isVpn = value; OnChanged(nameof(IsVpn)); } }

        private bool? _isProxy;
        public bool? IsProxy { get => _isProxy; set { _isProxy = value; OnChanged(nameof(IsProxy)); } }

        // ===== WHOIS / enrichment =====
        public string? WhoisRegistrar { get; set; }
        public string? WhoisOrganization { get; set; }
        public string? WhoisCountry { get; set; }
        public string? WhoisASN { get; set; }
        public string? WhoisAbuseContact { get; set; }

        // ===== Reputation =====
        public bool? ReputationIsMalicious { get; set; }
        public int? ReputationScore { get; set; }
        public int? ReputationReports { get; set; }
        public DateTime? ReputationLastSeen { get; set; }

        // ===== MQTT (wire-derived when populated by PacketHandler) =====
        // No MQTT payload or client credentials are retained here.
        public bool MqttPublishTopicObserved { get; set; }
        public bool? MqttRetain { get; set; }
        public bool MqttControlTopicObserved { get; set; }
        public bool MqttWillTopicObserved { get; set; }
        public bool MqttWillControlTopicObserved { get; set; }

        // ===== HTTP =====
        public string? HttpMethod { get; set; }
        public string? HttpHost { get; set; }
        public string? HttpUri { get; set; }
        public string? HttpUserAgent { get; set; }
        public string? HttpRequestHeaders { get; set; }

        // Derived from a wire-observed HTTP Authorization header before redaction.
        // The original credential and its Base64 representation are never retained.
        // Internal setter prevents arbitrary external record construction from claiming
        // this trusted capture-path observation.
        public bool HttpBasicDefaultCredentialObserved { get; internal set; }

        // JA4H (HTTP)
        private string? _ja4H;
        public string? Ja4H { get => _ja4H; set { _ja4H = value; OnChanged(nameof(Ja4H)); } }
        public string? HttpJa4h { get => _ja4H; set { _ja4H = value; OnChanged(nameof(HttpJa4h)); OnChanged(nameof(Ja4H)); } }

        // ===== TLS / JA3 / JA4 =====
        private string? _sni;
        public string? Sni { get => _sni; set { _sni = value; OnChanged(nameof(Sni)); OnChanged(nameof(TlsSni)); } }
        public string? TlsSni { get => _sni; set { _sni = value; OnChanged(nameof(TlsSni)); OnChanged(nameof(Sni)); } }

        private string? _alpn;
        public string? Alpn { get => _alpn; set { _alpn = value; OnChanged(nameof(Alpn)); OnChanged(nameof(TlsAlpn)); } }
        public string? TlsAlpn { get => _alpn; set { _alpn = value; OnChanged(nameof(TlsAlpn)); OnChanged(nameof(Alpn)); } }

        public string? TlsVersion { get; set; }
        public string? Ja3 { get; set; }

        private string? _ja4;
        public string? Ja4 { get => _ja4; set { _ja4 = value; OnChanged(nameof(Ja4)); OnChanged(nameof(TlsJa4)); } }
        public string? TlsJa4 { get => _ja4; set { _ja4 = value; OnChanged(nameof(TlsJa4)); OnChanged(nameof(Ja4)); } }

        private string? _ja4S;
        public string? Ja4S { get => _ja4S; set { _ja4S = value; OnChanged(nameof(Ja4S)); OnChanged(nameof(TlsJa4s)); } }
        public string? TlsJa4s { get => _ja4S; set { _ja4S = value; OnChanged(nameof(TlsJa4s)); OnChanged(nameof(Ja4S)); } }

        private string? _ja4X;
        public string? Ja4X { get => _ja4X; set { _ja4X = value; OnChanged(nameof(Ja4X)); OnChanged(nameof(TlsJa4x)); } }
        public string? TlsJa4x { get => _ja4X; set { _ja4X = value; OnChanged(nameof(TlsJa4x)); OnChanged(nameof(Ja4X)); } }

        private string? _ja4L;
        public string? Ja4L { get => _ja4L; set { _ja4L = value; OnChanged(nameof(Ja4L)); } }

        private string? _ja4LS;
        public string? Ja4LS { get => _ja4LS; set { _ja4LS = value; OnChanged(nameof(Ja4LS)); } }

        // TCP (SYN/SYN-ACK) fingerprints – alias names
        private string? _ja4T;
        public string? Ja4T { get => _ja4T; set { _ja4T = value; OnChanged(nameof(Ja4T)); OnChanged(nameof(TcpJa4t)); } }
        public string? TcpJa4t { get => _ja4T; set { _ja4T = value; OnChanged(nameof(TcpJa4t)); OnChanged(nameof(Ja4T)); } }

        private string? _ja4TS;
        public string? Ja4TS { get => _ja4TS; set { _ja4TS = value; OnChanged(nameof(Ja4TS)); OnChanged(nameof(TcpJa4ts)); } }
        public string? TcpJa4ts { get => _ja4TS; set { _ja4TS = value; OnChanged(nameof(TcpJa4ts)); OnChanged(nameof(Ja4TS)); } }

        // ===== SSH =====
        private string? _ja4SSH;
        public string? Ja4SSH { get => _ja4SSH; set { _ja4SSH = value; OnChanged(nameof(Ja4SSH)); OnChanged(nameof(SshJa4)); } }
        public string? SshJa4 { get => _ja4SSH; set { _ja4SSH = value; OnChanged(nameof(SshJa4)); OnChanged(nameof(Ja4SSH)); } }

        private string? _hassh;
        public string? Hassh { get => _hassh; set { _hassh = value; OnChanged(nameof(Hassh)); } }

        // ===== QUIC (new) =====
        public bool IsQuic { get; set; }
        public string? QuicVersion { get; set; }
        public string? QuicAlpn { get; set; }                // ALPN surfaced via MsQuic when available
        public string? QuicConnectionIdHash { get; set; }    // non-PII stable tag

        // ===== Certificate (from TLS) =====
        public string? CertIssuer { get; set; }
        public string? CertSubject { get; set; }
        public DateTime? CertValidFrom { get; set; }
        public DateTime? CertValidTo { get; set; }

        // ===== DNS =====
        public string? DnsQname { get; set; }
        public string? DnsQtype { get; set; }
        public string? DnsRcode { get; set; }
        public bool DnsIsResponse { get; set; }
        public string? DnsAnswers { get; set; }
        public int? DnsTtl { get; set; }

        // ===== GeoIP =====
        public string? SrcCountry { get; set; }
        public string? SrcCountryIso2 { get; set; }
        public double? SrcLat { get; set; }
        public double? SrcLon { get; set; }
        public string? DstCountry { get; set; }
        public string? DstCountryIso2 { get; set; }
        public double? DstLat { get; set; }
        public double? DstLon { get; set; }

        // ===== Timing (JA4L inputs) =====
        public DateTime? TcpSynAt { get; set; }
        public DateTime? TcpSynAckAt { get; set; }
        public double? RttEstimateMs { get; set; }
    }
}
