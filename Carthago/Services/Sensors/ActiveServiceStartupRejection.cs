// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Text.Json;

namespace Carthago.Services.Sensors;

internal enum ActiveServiceRejectionReason { NoValidGrant, PinnedGrantMismatch, SnmpCredentialUnavailable }

// Allowlisted pre-manager rejection only. No raw exception, profile, grant,
// credential or network details. Not a substitute for SCM or process evidence.
internal sealed class ActiveServiceStartupRejection
{
    internal const string FileName = "startup-rejection.json";
    private readonly string _root;
    private readonly int _pid;
    private readonly DateTimeOffset _started;
    private readonly string _configSha256;
    internal ActiveServiceStartupRejection(string root, int pid, DateTimeOffset started, string configSha256)
    { _root = root; _pid = pid; _started = started; _configSha256 = configSha256; }

    internal void Publish(ActiveServiceRejectionReason reason)
    {
        if (!Enum.IsDefined(reason)) throw new ArgumentOutOfRangeException(nameof(reason));
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 1, attemptId = Guid.NewGuid(),
            processId = _pid, processStartedUtc = _started, rejectedUtc = DateTimeOffset.UtcNow,
            configSha256 = _configSha256, reason = reason.ToString(), readinessPublished = false });
        string path = Path.Combine(_root, FileName);
        string temp = Path.Combine(_root, "rejection-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { stream.Write(bytes); stream.Flush(true); }
            File.Move(temp, path, overwrite: true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}
