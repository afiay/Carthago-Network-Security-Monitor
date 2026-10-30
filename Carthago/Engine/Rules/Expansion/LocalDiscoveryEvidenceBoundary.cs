// SPDX-License-Identifier: MIT
// GA R453-R460 — SOURCE CANDIDATE — UNVERIFIED.
// Missing rule-specific provenance is explicit and fails closed before generic
// name, port, path or timing scoring. This helper does not assert telemetry.
namespace Carthago.Engine.Rules.Expansion
{
    internal static class LocalDiscoveryEvidenceBoundary
    {
        internal static (string Code, string Detail)? GetMissingProducer(string ruleId)
            => ruleId switch
            {
                "R453" => ("MDNS_ENUMERATION_RATE_BASELINE_UNAVAILABLE",
                    "The packet parser can observe mDNS questions, but four packets in five minutes do not prove high-rate, distinct service enumeration without a calibrated source baseline and query-series provenance."),
                "R454" => ("SSDP_MSEARCH_RESPONSE_CORRELATION_UNAVAILABLE",
                    "Port 1900 and M-SEARCH vocabulary do not establish an attributed SSDP discovery request, correlated response or external-answer direction."),
                "R455" => ("AIRPLAY_NONMEDIA_HOST_ROLE_UNAVAILABLE",
                    "A wire-observed mDNS AirPlay service question does not prove that the querying asset is a non-media host; trusted asset-role inventory is absent."),
                "R456" => ("CHROMECAST_DISCOVERY_BURST_BASELINE_UNAVAILABLE",
                    "A Chromecast service query or casting port cannot prove an anomalous discovery burst without distinct per-source observations and a validated normal-discovery baseline."),
                "R457" => ("JETDIRECT_PRINTER_IDENTITY_AND_EXPOSURE_UNAVAILABLE",
                    "TCP/9100 or 631 alone cannot establish a JetDirect printer, a completed printing operation or unauthorized external access."),
                "R458" => ("IPP_OPERATION_AND_RESPONSE_UNAVAILABLE",
                    "HTTP POST on port 631 is not a decoded IPP operation, verified printer identity, successful print job or authenticated external-host policy."),
                "R459" => ("SMB_BROWSER_ELECTION_MESSAGE_UNAVAILABLE",
                    "SMB/NetBIOS ports and generic SMB traffic do not prove a parsed browser-election datagram or anomalous election state."),
                "R460" => ("NBNS_DISTINCT_NAME_SWEEP_UNAVAILABLE",
                    "UDP/137 and descriptive text cannot establish decoded NetBIOS name questions, distinct names/targets, or a per-source sweep window."),
                _ => null
            };
    }
}
