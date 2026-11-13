// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Contracts;

namespace Carthago.Services.Sensors;

/// <summary>Service-only storage and explicit pinned-grant execution.</summary>
public static class ActiveServiceWorker
{
    public static Task<int> ExecuteAsync(ActiveServiceOptions options, CancellationToken token, Action ready)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!string.Equals(identity.User?.Value, options.AccountSid, StringComparison.Ordinal))
            throw new InvalidOperationException("Service account SID mismatch.");
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(local)) throw new InvalidOperationException("Service account profile unavailable.");
        string root = Path.Combine(local, "Carthago", "active-service");
        // Provisioning must create this directory under the service account first.
        // No fallback to desktop stores or arbitrary caller-supplied storage paths.
        if (!Directory.Exists(root)) throw new InvalidOperationException("Service storage not provisioned.");
        for (string? path = Path.GetFullPath(root); path is not null; path = Path.GetDirectoryName(path))
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Service storage reparse point rejected.");
        foreach (var path in Directory.EnumerateFileSystemEntries(root))
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Service storage reparse point rejected.");
        var store = new ActiveSensorProfileStore(Path.Combine(root, "profiles.db"),
            vault: new SnmpCredentialVault(Path.Combine(root, "credentials.db")));
        var evidence = new ActiveEvidenceStore(Path.Combine(root, "evidence.db"));
        var pinned = options.Profiles.ToDictionary(p => p.ProfileId, p => p.GrantId, StringComparer.Ordinal);
        var args = new[] { "run" }.Concat(options.Profiles.SelectMany(p => new[] { "--profile", p.ProfileId })).ToArray();
        return ActiveSensorWorker.ExecuteCoreAsync(args, TextWriter.Null, TextWriter.Null, token, store,
            id => LocalLanDiscovery.GetLocalInterfaces(id), () => new ActiveSensorManager(save: evidence.Save),
            pinnedGrants: pinned, ready: ready);
    }
}
