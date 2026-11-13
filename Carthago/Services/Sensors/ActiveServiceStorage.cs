// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using Carthago.Contracts;

namespace Carthago.Services.Sensors;

internal static class ActiveServiceStorage
{
    internal const string ConfigName = "active-service.json";
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdminSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    internal static SecurityIdentifier CurrentAccount(string expected)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User ?? throw new InvalidOperationException("Windows identity unavailable.");
        // Use the strict configuration parser to keep account policy identical.
        var bytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new {
            schemaVersion = 1, accountSid = expected,
            profiles = new[] { new { profileId = new string('a', 64), grantId = "02702701-1234-4321-9999-000000000001" } }
        });
        _ = ActiveServiceConfiguration.Parse(bytes);
        if (sid.Value != expected) throw new InvalidOperationException("Service account SID mismatch.");
        return sid;
    }

    internal static bool Trusted(SecurityIdentifier sid, SecurityIdentifier account) =>
        sid.Equals(account) || sid.Equals(SystemSid) || sid.Equals(AdminSid);

    internal static string Root(SecurityIdentifier account, bool create)
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(local) || !Path.IsPathFullyQualified(local))
            throw new InvalidOperationException("Service account profile unavailable.");
        string parent = Path.Combine(local, "Carthago");
        CheckAncestors(local);
        if (create && !Directory.Exists(parent)) Directory.CreateDirectory(parent);
        CheckAncestors(parent);
        string root = Path.Combine(parent, "active-service");
        if (create && !Directory.Exists(root)) CreateProtectedDirectory(root, account);
        CheckTree(root, account);
        return root;
    }

    internal static void CheckAncestors(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Service storage reparse point rejected.");
    }

    internal static void CreateProtectedDirectory(string path, SecurityIdentifier account)
    {
        // Apply the protected DACL at creation, not after creating an exposed directory.
        var security = new DirectorySecurity();
        security.SetOwner(account);
        security.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { account, SystemSid, AdminSid })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).Create(security);
    }

    internal static void CheckTree(string root, SecurityIdentifier account)
    {
        CheckAncestors(root);
        var directory = new DirectoryInfo(root);
        var acl = directory.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        if (!acl.AreAccessRulesProtected) throw new InvalidOperationException("Service storage DACL must be protected.");
        CheckAcl(acl, account);
        foreach (var entry in directory.EnumerateFileSystemInfos())
        {
            if ((entry.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 ||
                entry is not FileInfo file)
                throw new InvalidOperationException("Unexpected service storage entry.");
            CheckAcl(file.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access), account);
        }
    }

    private static void CheckAcl(FileSystemSecurity acl, SecurityIdentifier account)
    {
        if (acl.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !Trusted(owner, account))
            throw new InvalidOperationException("Untrusted service storage owner.");
        bool accountAccess = false;
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow)
            {
                if (rule.IdentityReference is not SecurityIdentifier sid || !Trusted(sid, account))
                    throw new InvalidOperationException("Untrusted service storage access rule.");
                if (sid.Equals(account) && (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl &&
                    (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0) accountAccess = true;
            }
            else throw new InvalidOperationException("Unexpected service storage deny rule.");
        }
        if (!accountAccess) throw new InvalidOperationException("Service account access missing.");
    }

    internal static ActiveSensorProfileStore Store(string root) => new(Path.Combine(root, "profiles.db"),
        vault: Vault(root));
    internal static SnmpCredentialVault Vault(string root) => new(Path.Combine(root, "credentials.db"));
}
