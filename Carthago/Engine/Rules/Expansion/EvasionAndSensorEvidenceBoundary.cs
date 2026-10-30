// SPDX-License-Identifier: MIT
// GA R521-R530 — SOURCE CANDIDATE — UNVERIFIED.
// Missing independent producer contracts. Untrusted packet metadata, headers,
// Info, process labels and claimed health events must not assert these behaviors.
// This file does not authorize capture, decryption, or any new telemetry schema.
namespace Carthago.Engine.Rules.Expansion
{
    internal static class EvasionAndSensorEvidenceBoundary
    {
        internal static (string Code, string Detail)? GetMissingProducer(string ruleId)
            => ruleId switch
            {
                "R521" => ("HTTP_CONNECT_PROXY_PORT_POLICY_AND_SESSION_UNAVAILABLE",
                    "A decoded HTTP CONNECT request alone does not establish an unapproved proxy port or an established tunnel; trusted proxy-port policy and correlated session outcome are unavailable."),
                "R522" => ("WEBSOCKET_UPGRADE_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE",
                    "A WebSocket Upgrade header or IP-literal Host is not proof of a tunnel; correlated accepted upgrade, session behavior and approved endpoint policy are unavailable."),
                "R523" => ("DOMAIN_FRONTING_SNI_HTTP_AUTHORITY_CORRELATION_UNAVAILABLE",
                    "HTTP Host and TLS SNI fields on an uncorrelated record do not establish one encrypted connection's fronting behavior; correlated TLS/HTTP authority evidence is unavailable."),
                "R524" => ("ECH_PROVIDER_APPROVAL_AND_HANDSHAKE_PROVENANCE_UNAVAILABLE",
                    "ECH-like TLS labels do not prove ECH acceptance or an unapproved provider; trusted ECH handshake observation and provider approval policy are unavailable."),
                "R525" => ("QUIC_CID_ROTATION_SESSION_BASELINE_UNAVAILABLE",
                    "An isolated QUIC version or hashed connection ID does not establish a rotation burst; session-linked CID transitions and a calibrated baseline are unavailable."),
                "R526" => ("PACKET_SIZE_MIMICRY_CALIBRATED_BASELINE_UNAVAILABLE",
                    "Packet lengths alone cannot establish deliberate size mimicry; deduplicated per-flow timing, benign-reference distributions and calibrated anomaly criteria are unavailable."),
                "R527" => ("SLEEPY_BEACON_LONG_GAP_BASELINE_UNAVAILABLE",
                    "Sparse packet timestamps alone do not prove a sleepy beacon; complete capture coverage, independent intervals and calibrated host-specific baseline are unavailable."),
                "R528" => ("USER_AGENT_DISTINCT_REQUEST_BASELINE_UNAVAILABLE",
                    "A single client-controlled User-Agent is not a randomization burst; independently observed distinct HTTP requests, stable client attribution and an approved baseline are unavailable."),
                "R529" => ("SENSOR_HEARTBEAT_TRUSTED_HEALTH_PRODUCER_UNAVAILABLE",
                    "Packet text claiming missing heartbeat is not a trusted site/sensor health event; authenticated heartbeat source, site inventory, expected cadence and maintenance policy are unavailable."),
                "R530" => ("SENSOR_CLOCK_SKEW_TRUSTED_METRIC_PRODUCER_UNAVAILABLE",
                    "Packet text claiming clock drift is not a trusted sensor metric; authenticated time-offset samples, monotonic trend, calibrated threshold and clock source are unavailable."),
                _ => null
            };
    }
}
