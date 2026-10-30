// SPDX-License-Identifier: MIT
// GA R493-R500 — SOURCE CANDIDATE — UNVERIFIED.
// Packet/HTTP metadata cannot authenticate the local source file, clipboard
// origin, remote-desktop transfer channel, or completed outbound upload.
// This explicit evidence boundary introduces no payload or secret retention.
namespace Carthago.Engine.Rules.Expansion
{
    internal static class SensitiveTransferEvidenceBoundary
    {
        internal static (string Code, string Detail)? GetMissingProducer(string ruleId)
            => ruleId switch
            {
                "R493" => ("BROWSER_PASSWORD_STORE_FILE_UPLOAD_PROVENANCE_UNAVAILABLE",
                    "No trusted local browser credential-store file identity, process-to-file read, upload body association, or external transfer outcome reaches this rule."),
                "R494" => ("SSH_PRIVATE_KEY_FILE_UPLOAD_PROVENANCE_UNAVAILABLE",
                    "An id_rsa path, SSH port or HTTP request is not trusted proof of private-key file read, uploaded bytes, transfer direction, or outcome."),
                "R495" => ("KEEPASS_DATABASE_FILE_UPLOAD_PROVENANCE_UNAVAILABLE",
                    "A KeePass filename or process label cannot prove a specific KDBX file was opened and transferred to the observed destination."),
                "R496" => ("VPN_CONFIGURATION_FILE_UPLOAD_PROVENANCE_UNAVAILABLE",
                    "A VPN configuration filename, upload URI or generic POST does not establish trusted local configuration-file provenance or external upload."),
                "R497" => ("BROWSER_COOKIE_DATABASE_UPLOAD_PROVENANCE_UNAVAILABLE",
                    "Cookie vocabulary and HTTP traffic do not prove a browser cookie database was accessed and uploaded; cookie values must not be retained."),
                "R498" => ("CLIPBOARD_CONTENT_AND_SYNC_TRANSFER_PROVENANCE_UNAVAILABLE",
                    "Packet bytes and clipboard text labels do not establish a local clipboard event, its size, synchronization identity, or correlated upload."),
                "R499" => ("REMOTE_DESKTOP_FILE_CHANNEL_BURST_PROVENANCE_UNAVAILABLE",
                    "Network flows cannot identify authenticated remote-desktop file-transfer channel operations, distinct files, transfer direction, or a calibrated burst."),
                "R500" => ("ARCHIVE_CREATION_TO_CLOUD_UPLOAD_CORRELATION_UNAVAILABLE",
                    "Archive suffixes and cloud requests cannot prove ordered local archive creation, file identity, correlated upload, or server outcome."),
                _ => null
            };
    }
}
