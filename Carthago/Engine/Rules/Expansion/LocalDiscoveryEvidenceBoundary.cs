// SPDX-License-Identifier: MIT
// GA R453-R470 — SOURCE CANDIDATE — UNVERIFIED.
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
                "R461" => ("DHCP_DISTINCT_CLIENT_LEASE_EXHAUSTION_UNAVAILABLE",
                    "UDP/67-68 and DHCP labels do not prove distinct client identifiers, server lease exhaustion, or a source-attributed request burst."),
                "R462" => ("DHCP_OFFER_SERVER_AUTHORITY_UNAVAILABLE",
                    "A DHCP OFFER label does not prove a decoded server offer, trusted server identity, or a violation of approved DHCP server inventory."),
                "R463" => ("ARP_GRATUITOUS_RATE_BASELINE_UNAVAILABLE",
                    "ARP labels and repeated packets do not establish decoded gratuitous ARP announcements, unique observations, or a calibrated storm baseline."),
                "R464" => ("ARP_IP_MAC_BINDING_TRANSITIONS_UNAVAILABLE",
                    "ARP labels and MAC fields do not establish time-ordered conflicting IP-to-MAC bindings or exclude approved failover and mobility."),
                "R465" => ("IPV6_ROUTER_ADVERTISEMENT_PREFIX_HISTORY_UNAVAILABLE",
                    "Generic ICMPv6 metadata cannot prove decoded Router Advertisement prefix options, trusted router identity, or an unexpected SLAAC prefix transition."),
                "R466" => ("WIFI_CONTROLLER_IDENTITY_AND_PROBE_OUTCOME_UNAVAILABLE",
                    "HTTP GET/POST or controller vocabulary does not attest managed Wi-Fi controller identity, authorization, or a verified administration probe."),
                "R467" => ("CAPWAP_CONTROL_EXCHANGE_AND_CONTROLLER_POLICY_UNAVAILABLE",
                    "UDP/5246-5247 or CAPWAP labels do not prove decoded control exchange, external controller identity, or a policy violation."),
                "R468" => ("BLUETOOTH_GATEWAY_ASSET_ROLE_AND_EGRESS_UNAVAILABLE",
                    "TLS/443 and a Bluetooth gateway label cannot prove trusted gateway role, correlated outbound egress, or an unapproved destination."),
                "R469" => ("ADB_PROTOCOL_HANDSHAKE_AND_ACCESS_POLICY_UNAVAILABLE",
                    "TCP/5555 or an Android Debug Bridge label does not prove a decoded ADB handshake, successful access, or unauthorized device exposure."),
                "R470" => ("MDM_ENROLLMENT_OUTCOME_BURST_UNAVAILABLE",
                    "MDM URLs, HTTP methods or repeated traffic do not establish authenticated enrollment outcomes, distinct devices, or a calibrated burst."),
                _ => null
            };
    }
}
