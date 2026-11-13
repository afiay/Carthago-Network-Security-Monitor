// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Carthago.Contracts;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveServiceProvisioningTests : IDisposable
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("lab", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0"));
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-service-acl-" + Guid.NewGuid().ToString("N"));
    private static string[] Args(string kind = "Dns", string host = "lab.example", string port = "53") =>
        new[] { "--adapter", AdapterId.ToString("D"), "--source", "192.168.50.10", "--target", "192.168.50.11",
            "--sensor", kind, "--host", host, "--port", port, "--interval", "5", "--history", "true" };

    [Fact]
    public void ProfileRequiresExactLiveScopeAndCanonicalParameters()
    {
        var p = ActiveServiceProvisioning.ParseProfile(Args(), _ => new[] { Adapter }, _ => true);
        Assert.Equal(ActiveSensorKind.Dns, p.Kind);
        Assert.Throws<ArgumentException>(() => ActiveServiceProvisioning.ParseProfile(Args(), _ => new[] { Adapter, Adapter }, _ => true));
        Assert.Throws<ArgumentException>(() => ActiveServiceProvisioning.ParseProfile(Args(port: "54"), _ => new[] { Adapter }, _ => true));
        Assert.Throws<ArgumentException>(() => ActiveServiceProvisioning.ParseProfile(Args("Gateway", "", "0"), _ => new[] { Adapter }, _ => false));
    }

    [Fact]
    public void ConfigurationRoundTripPinsGrantAndContainsNoSecrets()
    {
        var id = new string('a', 64); var grant = Guid.NewGuid();
        byte[] bytes = ActiveServiceProvisioning.BuildConfiguration("S-1-5-21-100-200-300-1001", new[] { new ActiveServiceSelection(id, grant) });
        var parsed = ActiveServiceConfiguration.Parse(bytes);
        Assert.Equal(grant, Assert.Single(parsed.Profiles).GrantId);
        using var json = JsonDocument.Parse(bytes);
        Assert.Equal(3, System.Linq.Enumerable.Count(json.RootElement.EnumerateObject()));
        Assert.Throws<InvalidDataException>(() => ActiveServiceProvisioning.BuildConfiguration(parsed.AccountSid,
            new[] { new ActiveServiceSelection(id, grant), new ActiveServiceSelection(id, Guid.NewGuid()) }));
    }

    [Fact]
    public void ProtectedStorageAcceptsInheritedFilesAndRejectsUnexpectedAccess()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var account = identity.User!;
        ActiveServiceStorage.CreateProtectedDirectory(_dir, account);
        string path = Path.Combine(_dir, "fixture.db");
        File.WriteAllText(path, "fixture");
        ActiveServiceStorage.CheckTree(_dir, account);
        var file = new FileInfo(path);
        var acl = file.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.ReadData, AccessControlType.Allow));
        file.SetAccessControl(acl);
        Assert.Throws<InvalidOperationException>(() => ActiveServiceStorage.CheckTree(_dir, account));
    }

    [Fact]
    public void ConfigurationWriterReplacesOnlyWithValidatedConfiguration()
    {
        using var identity = WindowsIdentity.GetCurrent();
        ActiveServiceStorage.CreateProtectedDirectory(_dir, identity.User!);
        var bytes = ActiveServiceProvisioning.BuildConfiguration("S-1-5-21-100-200-300-1001",
            new[] { new ActiveServiceSelection(new string('a', 64), Guid.NewGuid()) });
        ActiveServiceProvisioning.WriteConfiguration(_dir, bytes);
        string path = Path.Combine(_dir, ActiveServiceStorage.ConfigName);
        Assert.Equal(bytes, File.ReadAllBytes(path));
        Assert.ThrowsAny<Exception>(() => ActiveServiceProvisioning.WriteConfiguration(_dir, new byte[] { 1 }));
        Assert.Equal(bytes, File.ReadAllBytes(path));
        ActiveServiceStorage.CheckTree(_dir, identity.User!);
    }

    [Fact]
    public void UnexpectedDirectoryInStorageRejected()
    {
        using var identity = WindowsIdentity.GetCurrent();
        ActiveServiceStorage.CreateProtectedDirectory(_dir, identity.User!);
        Directory.CreateDirectory(Path.Combine(_dir, "unexpected"));
        Assert.Throws<InvalidOperationException>(() => ActiveServiceStorage.CheckTree(_dir, identity.User!));
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
