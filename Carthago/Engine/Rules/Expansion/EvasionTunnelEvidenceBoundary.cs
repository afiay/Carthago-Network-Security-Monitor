// SPDX-License-Identifier: MIT
// GA R513-R520 — SOURCE CANDIDATE — UNVERIFIED.
// SSH banners, ports, QUIC version tags, HTTP paths, SNI and client process
// labels are not authenticated forwarding or tunnel-session provenance.
// No credential, command-line or decrypted payload capture is introduced.
namespace Carthago.Engine.Rules.Expansion
{
    internal static class EvasionTunnelEvidenceBoundary
    {
        internal static (string Code, string Detail)? GetMissingProducer(string ruleId)
            => ruleId switch
            {
                "R513" => ("SSH_DYNAMIC_FORWARD_COMMAND_AND_SOCKET_PROVENANCE_UNAVAILABLE",
                    "An SSH connection or banner cannot establish a dynamic SOCKS listener or -D forwarding command; trusted process/socket attribution and forwarding-session correlation are unavailable."),
                "R514" => ("CHISEL_AUTHENTICATED_HANDSHAKE_PROVENANCE_UNAVAILABLE",
                    "A WebSocket upgrade, generic /tunnel path, client process label or port does not establish a Chisel handshake; authenticated agent/session evidence is unavailable."),
                "R515" => ("FRP_AUTHENTICATED_HANDSHAKE_PROVENANCE_UNAVAILABLE",
                    "FRP default ports, process labels and generic HTTP text do not establish an frpc/frps handshake or tunnel registration; trusted agent/session evidence is unavailable."),
                "R516" => ("CLOUDFLARED_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE",
                    "QUIC/TLS traffic, port 7844 or cloudflared-looking process text cannot establish an authenticated Cloudflare Tunnel session; connector identity and session provenance are unavailable."),
                "R517" => ("NGROK_AGENT_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE",
                    "An ngrok hostname, API path or spoofed authtoken header cannot establish an ngrok v2 agent handshake or authorized tunnel session; authenticated agent/session evidence is unavailable."),
                "R518" => ("SSH_REVERSE_FORWARD_COMMAND_AND_LISTENER_PROVENANCE_UNAVAILABLE",
                    "An SSH banner or port 22 cannot distinguish reverse -R forwarding from ordinary SSH; trusted process arguments, remote listener and forwarding correlation are unavailable."),
                "R519" => ("DOQ_ALPN_RESOLVER_IDENTITY_AND_APPROVAL_UNAVAILABLE",
                    "A QUIC version tag, DNS name or UDP/853 port does not establish DNS-over-QUIC ALPN doq, resolver identity or unapproved status; authenticated resolver inventory and session attribution are unavailable."),
                "R520" => ("MASQUE_CONNECT_UDP_HTTP3_SESSION_PROVENANCE_UNAVAILABLE",
                    "Generic HTTP CONNECT, QUIC or a connect-udp path does not establish HTTP/3 extended CONNECT with :protocol connect-udp and a correlated MASQUE proxy session; no HTTP/3 session decoder is connected."),
                _ => null
            };
    }
}
