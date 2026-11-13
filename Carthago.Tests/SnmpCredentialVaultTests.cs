// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Carthago.Services;
using Carthago.Services.Sensors;
using LiteDB;
using Xunit;

namespace Carthago.Tests;

public sealed class SnmpCredentialVaultTests : IDisposable
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("lab", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0"));
    private static SnmpCredentialScope Scope(string target = "192.168.50.11") =>
        SnmpCredentialScope.Create(AdapterId, Adapter, IPAddress.Parse(target));
    private static SnmpCredential Secret() => new("lab-user-unique", "auth-phrase-unique-123", "priv-phrase-unique-456");
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-snmp-vault-" + Guid.NewGuid().ToString("N"));
    private string DbPath => Path.Combine(_dir, "vault.db");
    private SnmpCredentialVault Vault() => new(DbPath);

    [Fact]
    public void CurrentUserRoundTripAndNoPlaintextRecord()
    {
        var scope = Scope();
        var secret = Secret();
        var generation = Vault().Save(scope, secret);
        Assert.True(generation.HasValue);
        Assert.Equal(generation, Vault().GetGeneration(scope));
        var loaded = Assert.IsType<SnmpCredential>(Vault().Load(scope, generation.Value));
        Assert.Equal(secret.User, loaded.User);
        Assert.Equal(secret.Authentication, loaded.Authentication);
        Assert.Equal(secret.Privacy, loaded.Privacy);
        using (var db = new LiteDatabase(DbPath))
        {
            var row = db.GetCollection<SnmpCredentialVault.Entry>("snmp_credentials").FindById(scope.Key);
            Assert.NotNull(row);
            Assert.NotEmpty(row.ProtectedPayload);
            Assert.NotEqual(Encoding.ASCII.GetBytes(secret.Authentication), row.ProtectedPayload);
        }
        foreach (var file in Directory.GetFiles(_dir))
        {
            var text = Encoding.ASCII.GetString(File.ReadAllBytes(file));
            Assert.DoesNotContain(secret.User, text);
            Assert.DoesNotContain(secret.Authentication, text);
            Assert.DoesNotContain(secret.Privacy, text);
        }
        Assert.DoesNotContain(secret.Authentication, loaded.ToString());
    }

    [Fact]
    public void RotationInvalidatesOldGenerationAndDeletionCannotBeReversed()
    {
        var scope = Scope();
        var first = Vault().Save(scope, Secret());
        Assert.True(first.HasValue);
        var second = Vault().Save(scope, new SnmpCredential("lab-user", "new-auth-123", "new-priv-456"));
        Assert.True(second.HasValue);
        Assert.NotEqual(first, second);
        Assert.Null(Vault().Load(scope, first.Value));
        Assert.Equal("new-auth-123", Vault().Load(scope, second.Value)?.Authentication);
        Assert.True(Vault().Delete(scope));
        Assert.Null(Vault().GetGeneration(scope));
        Assert.Null(Vault().Load(scope, second.Value));
        Assert.False(Vault().Delete(scope));
        var third = Vault().Save(scope, Secret());
        Assert.True(third.HasValue);
        Assert.NotEqual(second, third);
        Assert.Null(Vault().Load(scope, second.Value));
    }

    [Fact]
    public void ExactScopeIsolationAndInvalidScopeRejected()
    {
        var scope = Scope();
        var generation = Vault().Save(scope, Secret());
        Assert.True(generation.HasValue);
        foreach (var other in new[]
        {
            Scope("192.168.50.12"), scope with { AdapterId = Guid.NewGuid() },
            scope with { Source = "192.168.50.20" }, scope with { Mask = "255.255.255.128" }
        })
        {
            Assert.Null(Vault().GetGeneration(other));
            Assert.Null(Vault().Load(other, generation.Value));
            Assert.False(Vault().Delete(other));
        }
        Assert.Null(Vault().Save(scope with { Target = "8.8.8.8" }, Secret()));
        Assert.Null(Vault().Save(scope with { Mask = "255.0.255.0" }, Secret()));
        Assert.Throws<ArgumentException>(() => Scope("8.8.8.8"));
        Assert.NotNull(Vault().Load(scope, generation.Value));
    }

    [Fact]
    public void CopiedCiphertextCannotDecryptUnderOtherScopeOrGeneration()
    {
        var scope = Scope();
        var other = Scope("192.168.50.12");
        var generation = Vault().Save(scope, Secret());
        Assert.True(generation.HasValue);
        var newGeneration = Guid.NewGuid();
        using (var db = new LiteDatabase(DbPath))
        {
            var rows = db.GetCollection<SnmpCredentialVault.Entry>("snmp_credentials");
            var original = rows.FindById(scope.Key);
            rows.Insert(new SnmpCredentialVault.Entry { Id = other.Key, Generation = generation.Value,
                ProtectedPayload = original.ProtectedPayload });
            original.Generation = newGeneration;
            rows.Update(original);
        }
        Assert.Null(Vault().Load(other, generation.Value));
        Assert.Null(Vault().Load(scope, newGeneration));
    }

    [Fact]
    public void TamperedCiphertextFailsClosed()
    {
        var scope = Scope();
        var generation = Vault().Save(scope, Secret());
        Assert.True(generation.HasValue);
        using (var db = new LiteDatabase(DbPath))
        {
            var rows = db.GetCollection<SnmpCredentialVault.Entry>("snmp_credentials");
            var row = rows.FindById(scope.Key);
            row.ProtectedPayload[row.ProtectedPayload.Length / 2] ^= 0xff;
            rows.Update(row);
        }
        Assert.Null(Vault().Load(scope, generation.Value));
    }

    [Fact]
    public void MissingAndCorruptDatabaseFailClosedWithoutReplacement()
    {
        var scope = Scope();
        Assert.Null(Vault().GetGeneration(scope));
        Assert.Null(Vault().Load(scope, Guid.NewGuid()));
        Assert.False(Directory.Exists(_dir));
        Directory.CreateDirectory(_dir);
        var bytes = Enumerable.Repeat((byte)0xa5, 8192).ToArray();
        File.WriteAllBytes(DbPath, bytes);
        Assert.Null(Vault().Save(scope, Secret()));
        Assert.Null(Vault().Load(scope, Guid.NewGuid()));
        Assert.Equal(bytes, File.ReadAllBytes(DbPath));
    }

    [Fact]
    public void InvalidCredentialsRejectedBeforeStorage()
    {
        Assert.Throws<ArgumentException>(() => new SnmpCredential("bad user", "authphrase", "privphrase"));
        Assert.Throws<ArgumentException>(() => new SnmpCredential("user", "short", "privphrase"));
        Assert.Throws<ArgumentException>(() => new SnmpCredential("user", "authphrase", "bad\nphrase"));
        Assert.False(Directory.Exists(_dir));
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
