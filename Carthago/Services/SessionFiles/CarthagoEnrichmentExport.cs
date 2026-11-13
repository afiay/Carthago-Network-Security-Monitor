// SPDX-License-Identifier: MIT
using Carthago.Models;

namespace Carthago.Services.SessionFiles;

// Passive projection: preserve unknowns and provenance, never infer from names or ports.
// Include every retained traffic row so unavailable enrichment is visible in coverage.
internal static class CarthagoEnrichmentExport
{
    internal static object Project(TrafficRecord t) => new
    {
        t.Id, t.Source, t.Destination,
        t.SrcIpScope, t.DstIpScope, t.SrcIsLocalHost, t.DstIsLocalHost,
        t.CaptureBackend, t.CaptureInterfaceId, t.CaptureInterfaceName,
        t.CaptureInterfaceType, t.CaptureTunnelHint, t.CaptureInterfaceEvidence,
        t.ProcessName, t.ProcessId, t.ProcessAttribution,
        t.NetworkType, t.IsVpn, t.IsProxy, t.LocalVpnProcessHint, t.VpnPortHint,
        t.VpnClassificationIp, t.VpnClassificationConfidence, t.VpnEnrichmentStatus,
        t.SrcCountry, t.SrcCountryIso2, t.SrcCity, t.SrcLat, t.SrcLon, t.SrcAsn, t.SrcAsnOrganization,
        t.DstCountry, t.DstCountryIso2, t.DstCity, t.DstLat, t.DstLon, t.DstAsn, t.DstAsnOrganization,
        t.WhoisLookupIp, t.WhoisEnrichmentStatus, t.WhoisRegistrar, t.WhoisOrganization,
        t.WhoisCountry, t.WhoisASN, t.WhoisAbuseContact,
        t.ReputationLookupIp, t.ReputationEnrichmentStatus, t.ReputationIsMalicious,
        t.ReputationScore, t.ReputationReports, t.ReputationLastSeen,
        t.DnsCorrelatedNames, t.DnsCorrelatedNameCount, t.DnsCorrelationEvidence, t.DnsSniAgreement,
        t.TlsCorrelatedSni, t.TlsCorrelatedClientAlpn, t.TlsCorrelatedNegotiatedVersion,
        t.TlsCorrelatedNegotiatedAlpn, t.TlsCorrelatedCertificateSha256,
        t.TlsCorrelatedCertificateNameStatus, t.TlsCorrelationEvidence
    };
}
