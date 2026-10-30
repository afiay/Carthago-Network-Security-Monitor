// SPDX-License-Identifier: MIT
// GA R501-R510 — SOURCE CANDIDATE — UNVERIFIED.
// Network and HTTP metadata cannot authenticate multipart part filenames,
// request-body contents, distinct completed provider uploads, local process
// execution, or object-write outcomes. No payload/credential retention added.
namespace Carthago.Engine.Rules.Expansion
{
    internal static class DataLossUploadEvidenceBoundary
    {
        internal static (string Code, string Detail)? GetMissingProducer(string ruleId)
            => ruleId switch
            {
                "R501" => ("MULTIPART_PART_FILENAME_ENTROPY_AND_UPLOAD_CORRELATION_UNAVAILABLE",
                    "HTTP request headers do not contain multipart part filenames; no bounded, privacy-safe multipart part parser, filename entropy classification, body association or upload outcome is connected."),
                "R502" => ("DATA_URI_REQUEST_BODY_AND_UPLOAD_VOLUME_UNAVAILABLE",
                    "An HTTP request target mentioning data: or base64 is not an observed POST body; no bounded data-URI body classifier or correlated transmitted byte count is available."),
                "R503" => ("PASTEBIN_POST_RESPONSE_AND_DISTINCT_BULK_UNAVAILABLE",
                    "Paste service host/path and POST method do not establish distinct completed raw posts, correlated responses, or calibrated bulk upload behavior."),
                "R504" => ("GIST_SECRET_CONTENT_AND_CREATE_OUTCOME_UNAVAILABLE",
                    "GitHub host and Gist API request shape cannot establish that secret content was sent, that a Gist was created, or that a sensitive file was exposed."),
                "R505" => ("DISCORD_ATTACHMENT_UPLOAD_AND_BURST_CORRELATION_UNAVAILABLE",
                    "Discord host, CDN retrieval and HTTP request labels do not prove distinct attachment upload operations, message outcomes, or a calibrated burst."),
                "R506" => ("TELEGRAM_DOCUMENT_UPLOAD_AND_BURST_CORRELATION_UNAVAILABLE",
                    "Telegram API host, bot method text or encrypted traffic cannot attest sendDocument content, upload outcomes, or distinct document burst events."),
                "R507" => ("MEGA_UPLOAD_TRANSACTION_AND_OUTCOME_UNAVAILABLE",
                    "MEGA hostnames and HTTP method/packet sizes do not identify a completed upload transaction or distinguish approved synchronization."),
                "R508" => ("RCLONE_PROCESS_USERAGENT_AND_EGRESS_PROVENANCE_UNAVAILABLE",
                    "A client-supplied User-Agent and process-name enrichment do not authenticate rclone execution or correlate an outbound file transfer; a UA match alone is not exfiltration."),
                "R509" => ("RSYNC_PUSH_DIRECTION_AND_REMOTE_OUTCOME_UNAVAILABLE",
                    "TCP/873, SSH/22, rsync process text or CONNECT cannot establish native rsync sender/receiver direction, remote file write, or completed external push."),
                "R510" => ("S3_COMPATIBLE_ENDPOINT_IDENTITY_AND_UPLOAD_OUTCOME_UNAVAILABLE",
                    "An S3-looking hostname, SigV4-shaped request or generic PUT does not establish an unknown/unapproved endpoint, authenticated object write, or correlated response."),
                _ => null
            };
    }
}
