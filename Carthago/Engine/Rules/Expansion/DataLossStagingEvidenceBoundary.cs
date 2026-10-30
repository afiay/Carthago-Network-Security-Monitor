// SPDX-License-Identifier: MIT
// GA R511-R512 — SOURCE CANDIDATE — UNVERIFIED.
// Network metadata cannot attest a database export, sensitive local file,
// personal-mail recipient or completed correlated upload. No payload retained.
namespace Carthago.Engine.Rules.Expansion
{
    internal static class DataLossStagingEvidenceBoundary
    {
        internal static (string Code, string Detail)? GetMissingProducer(string ruleId)
            => ruleId switch
            {
                "R511" => ("DB_EXPORT_PROCESS_FILE_AND_UPLOAD_CORRELATION_UNAVAILABLE",
                    "A database client name, HTTP POST/PUT and packet length do not prove a local database export followed by a correlated completed external upload; trusted file/process and transfer outcomes are unavailable."),
                "R512" => ("SENSITIVE_FILE_PERSONAL_EMAIL_DELIVERY_PROVENANCE_UNAVAILABLE",
                    "An email hostname, filename text or HTTP request does not establish a sensitive local file, a verified personal-mail recipient, or successful delivery; privacy-preserving file and mail audit correlation is unavailable."),
                _ => null
            };
    }
}
