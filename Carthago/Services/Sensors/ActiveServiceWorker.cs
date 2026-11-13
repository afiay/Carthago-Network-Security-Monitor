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
    public static Task<int> ExecuteAsync(string configPath, CancellationToken token, Action ready)
    {
        var options = ActiveServiceConfiguration.Load(configPath);
        var account = ActiveServiceStorage.CurrentAccount(options.AccountSid);
        string root = ActiveServiceStorage.Root(account, create: false);
        if (!string.Equals(Path.GetFullPath(configPath), Path.Combine(root, ActiveServiceStorage.ConfigName), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Service configuration must be the provisioned account-local file.");
        // Re-read after verifying the protected file and account-local location.
        options = ActiveServiceConfiguration.Load(configPath);
        if (options.AccountSid != account.Value) throw new InvalidOperationException("Service account SID mismatch.");
        var store = ActiveServiceStorage.Store(root);
        var evidence = new ActiveEvidenceStore(Path.Combine(root, "evidence.db"));
        using var process = System.Diagnostics.Process.GetCurrentProcess();
        var health = new ActiveServiceHealthPublisher(root, Guid.NewGuid(), process.Id,
            new DateTimeOffset(process.StartTime.ToUniversalTime()));
        var pinned = options.Profiles.ToDictionary(p => p.ProfileId, p => p.GrantId, StringComparer.Ordinal);
        var args = new[] { "run" }.Concat(options.Profiles.SelectMany(p => new[] { "--profile", p.ProfileId })).ToArray();
        return ActiveSensorWorker.ExecuteCoreAsync(args, TextWriter.Null, TextWriter.Null, token, store,
            id => LocalLanDiscovery.GetLocalInterfaces(id), () => new ActiveSensorManager(save: evidence.Save),
            pinnedGrants: pinned, ready: ready, sample: health.Sample);
    }
}
