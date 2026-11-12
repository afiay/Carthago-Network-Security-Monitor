// SPDX-License-Identifier: MIT
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using Carthago.Models;

namespace Carthago.Services;

// Read-only projection of one retained record. No network calls or detector-field mutation.
// Provider endpoint provenance and correlated values remain explicitly separate.
internal static class ConnectionIntelligenceEvidence
{
    internal static IReadOnlyList<KeyValuePair<string, string>> Build(TrafficRecord row)
    {
        var fields = new List<KeyValuePair<string, string>>();
        void Add(string key, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value)) fields.Add(new(key, value));
        }
        string? Bool(bool? v) => v.HasValue ? v.Value ? "Yes" : "No" : null;
        string? Number(long? v) => v?.ToString(CultureInfo.InvariantCulture);
        string Endpoint(string? ip)
        {
            if (!IPAddress.TryParse(ip, out var address)) return "Endpoint unspecified";
            address = EndpointIpEnrichment.Normalize(address);
            bool Matches(string? value) => IPAddress.TryParse(value, out var other)
                && address.Equals(EndpointIpEnrichment.Normalize(other));
            bool src = Matches(row.Source), dst = Matches(row.Destination);
            return src && dst ? "Both packet endpoints" : src ? "Source endpoint" : dst ? "Destination endpoint" : "Other endpoint";
        }

        Add("Capture · backend", row.CaptureBackend);
        Add("Capture · interface", row.CaptureInterfaceName);
        Add("Capture · interface ID", row.CaptureInterfaceId);
        Add("Capture · interface type", row.CaptureInterfaceType);
        Add("Capture · interface evidence", row.CaptureInterfaceEvidence);
        Add("Capture · tunnel hint (observation point)", row.CaptureTunnelHint);
        Add("Endpoints · source is local host", Bool(row.SrcIsLocalHost));
        Add("Endpoints · destination is local host", Bool(row.DstIsLocalHost));
        Add("Host · process attribution", row.ProcessAttribution);
        Add("Host · local VPN process hint", Bool(row.LocalVpnProcessHint));
        Add("GeoIP · source city", row.SrcCity);
        Add("GeoIP · source ASN", Number(row.SrcAsn));
        Add("GeoIP · source ASN organization", row.SrcAsnOrganization);
        Add("GeoIP · destination city", row.DstCity);
        Add("GeoIP · destination ASN", Number(row.DstAsn));
        Add("GeoIP · destination ASN organization", row.DstAsnOrganization);
        Add("WHOIS · status", row.WhoisEnrichmentStatus);
        Add("WHOIS · lookup IP", row.WhoisLookupIp);
        if (row.WhoisLookupIp != null) Add("WHOIS · endpoint provenance", Endpoint(row.WhoisLookupIp));
        Add("Reputation · status", row.ReputationEnrichmentStatus);
        Add("Reputation · lookup IP", row.ReputationLookupIp);
        if (row.ReputationLookupIp != null) Add("Reputation · endpoint provenance", Endpoint(row.ReputationLookupIp));
        // A zero score is valid evidence, but absent lookup provenance must not
        // silently turn an old/default score into a clean endpoint assessment.
        if (!string.IsNullOrWhiteSpace(row.ReputationLookupIp) && row.ReputationEnrichmentStatus == "Success")
        {
            Add("Reputation · abuse score", Number(row.ReputationScore));
            Add("Reputation · reports", Number(row.ReputationReports));
        }
        Add("VPN inference · status", row.VpnEnrichmentStatus);
        Add("VPN inference · classification IP", row.VpnClassificationIp);
        if (row.VpnClassificationIp != null) Add("VPN inference · endpoint provenance", Endpoint(row.VpnClassificationIp));
        if (row.VpnEnrichmentStatus == "Success" && row.VpnClassificationIp != null)
            Add("VPN inference · heuristic score", Number(row.VpnClassificationConfidence));
        Add("VPN inference · port hint", Bool(row.VpnPortHint));

        Add("DNS correlation · candidate names", row.DnsCorrelatedNames);
        Add("DNS correlation · candidate count", Number(row.DnsCorrelatedNameCount));
        Add("DNS correlation · evidence", row.DnsCorrelationEvidence);
        Add("DNS correlation · observed SNI agreement", row.DnsSniAgreement);
        Add("TLS observed · negotiated version", row.TlsObservedNegotiatedVersion);
        Add("TLS observed · negotiated ALPN", row.TlsObservedNegotiatedAlpn);
        Add("TLS observed · certificate SHA-256", row.TlsCertificateSha256);
        Add("TLS observed · certificate DNS SAN", row.TlsCertificateDnsNames);
        Add("TLS observed · certificate SAN status", row.TlsCertificateNameStatus);
        Add("TLS observed · certificate time validity (not trust)", row.TlsCertificateValidityStatus);
        Add("TLS correlation · SNI", row.TlsCorrelatedSni);
        Add("TLS correlation · client offered ALPN", row.TlsCorrelatedClientAlpn);
        Add("TLS correlation · negotiated version", row.TlsCorrelatedNegotiatedVersion);
        Add("TLS correlation · negotiated ALPN", row.TlsCorrelatedNegotiatedAlpn);
        Add("TLS correlation · certificate SHA-256", row.TlsCorrelatedCertificateSha256);
        Add("TLS correlation · SNI/SAN agreement (not trust)", row.TlsCorrelatedCertificateNameStatus);
        Add("TLS correlation · evidence", row.TlsCorrelationEvidence);
        return fields;
    }
}
