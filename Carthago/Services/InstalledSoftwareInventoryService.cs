// SPDX-License-Identifier: MIT
// File: Services/InstalledSoftwareInventoryService.cs

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace Carthago.Services
{
    /// <summary>
    /// Enumerates installed software via the standard Uninstall registry keys (HKLM/HKCU,
    /// 32-bit and 64-bit views) and provides advanced integrity / exposure heuristics.
    ///
    /// This complements RootkitDetectorService (kernel drivers) with user-mode software inventory.
    /// </summary>
    public sealed class InstalledSoftwareInventoryService
    {
        public sealed class InstalledAppRecord
        {
            public string Name { get; init; } = string.Empty;
            public string? Version { get; init; }
            public string? Publisher { get; init; }
            public string? InstallLocation { get; init; }
            public string? InstallDateRaw { get; init; }
            public DateTimeOffset? InstallDate { get; init; }
            public string? UninstallString { get; init; }

            /// <summary>Source hive/view (e.g., HKLM-64, HKLM-32, HKCU-64, HKCU-32).</summary>
            public string Source { get; init; } = string.Empty;

            /// <summary>x86/x64/Unknown based on registry view.</summary>
            public string Architecture { get; init; } = "Unknown";

            /// <summary>Whether the entry is marked as a system component (often hidden in ARP).</summary>
            public bool IsSystemComponent { get; init; }

            /// <summary>InstallLocation is under a user-writable directory (profile, temp, etc.).</summary>
            public bool UserWritableLocation { get; init; }

            /// <summary>No DisplayVersion recorded.</summary>
            public bool MissingVersion { get; init; }

            /// <summary>Very weak heuristic: publisher looks generic or empty.</summary>
            public bool LowReputationPublisher { get; init; }

            /// <summary>True if the entry is primarily registered under HKCU.</summary>
            public bool IsPerUserInstall { get; init; }

            /// <summary>True if this looks like a browser / VPN / packet tool / remote / etc.</summary>
            public bool IsNetworkFacing { get; init; }

            /// <summary>True if this is very likely a remote access / remote control tool.</summary>
            public bool IsRemoteAccessTool { get; init; }

            /// <summary>True if this is a VM / emulation / virtualization / network lab tool.</summary>
            public bool IsVirtualizationOrEmulation { get; init; }

            /// <summary>True if this is an AV / EDR / security suite product.</summary>
            public bool IsSecurityProduct { get; init; }

            /// <summary>True if there is an uninstall command registered.</summary>
            public bool HasUninstallEntry { get; init; }

            /// <summary>True if InstallLocation points to an existing file/folder.</summary>
            public bool InstallLocationExists { get; init; }

            /// <summary>
            /// Very rough hygiene signal: we have a location but no uninstall entry,
            /// or we have an uninstall entry but the location is missing.
            /// </summary>
            public bool IsOrphanedInstall { get; init; }

            /// <summary>Age in days since installation, or -1 if unknown.</summary>
            public int AgeInDays { get; init; }

            /// <summary>High-level category (Browser, DevTool, NetworkTool, RemoteAccess, Security, Virtualization, General).</summary>
            public string Category { get; init; } = "General";

            /// <summary>Exposure-related score (user-writable, per-user, network facing, remote access, etc.).</summary>
            public int ExposureScore { get; init; }

            /// <summary>Hygiene-related score (missing version, low reputation, orphaned, old network tools, etc.).</summary>
            public int HygieneScore { get; init; }

            /// <summary>Simple numeric score 0–100 for "how much attention this deserves".</summary>
            public int Score { get; init; }

            public string Risk =>
                Score >= 80 ? "High" :
                Score >= 50 ? "Medium" :
                Score >= 20 ? "Low" :
                "Info";

            /// <summary>Human-readable flags (semicolon separated) that explain why this was scored.</summary>
            public string Flags { get; init; } = string.Empty;
        }

        public sealed class AppInventoryResult
        {
            public DateTimeOffset ScanTime { get; init; } = DateTimeOffset.UtcNow;
            public List<InstalledAppRecord> Apps { get; init; } = new();
        }

        /// <summary>
        /// Describes how an uninstall should be executed. Phase 2: the UI can take this and
        /// actually launch the uninstall with user confirmation.
        /// </summary>
        public sealed class UninstallPlan
        {
            /// <summary>Whether we believe this can be safely uninstalled via the UninstallString.</summary>
            public bool CanUninstall { get; init; }

            /// <summary>Short reason for why uninstall is not allowed / or general note.</summary>
            public string Reason { get; init; } = string.Empty;

            /// <summary>Parsed executable path (if we could split the command line).</summary>
            public string? FileName { get; init; }

            /// <summary>Arguments for the uninstall executable.</summary>
            public string? Arguments { get; init; }

            /// <summary>Whether to use shell execute (usually true for uninstallers).</summary>
            public bool UseShellExecute { get; init; }

            /// <summary>
            /// Hint that this likely requires elevation (HKLM / Program Files / Windows).
            /// The UI can use this to warn the user.
            /// </summary>
            public bool RequiresElevationHint { get; init; }

            /// <summary>The raw UninstallString from the registry, for logging / display.</summary>
            public string? RawUninstallString { get; init; }

            /// <summary>Rough uninstall type (Msi, Exe, Unknown).</summary>
            public string? Kind { get; init; }
        }

        public AppInventoryResult Scan()
        {
            var records = new List<InstalledAppRecord>();

            // HKLM – machine wide
            ScanUninstallKey(
                baseKey: RegistryHive.LocalMachine,
                view: RegistryView.Registry64,
                sourceLabel: "HKLM-64",
                arch: "x64",
                records);

            ScanUninstallKey(
                baseKey: RegistryHive.LocalMachine,
                view: RegistryView.Registry32,
                sourceLabel: "HKLM-32",
                arch: "x86",
                records);

            // HKCU – per-user
            ScanUninstallKey(
                baseKey: RegistryHive.CurrentUser,
                view: RegistryView.Registry64,
                sourceLabel: "HKCU-64",
                arch: "x64",
                records);

            ScanUninstallKey(
                baseKey: RegistryHive.CurrentUser,
                view: RegistryView.Registry32,
                sourceLabel: "HKCU-32",
                arch: "x86",
                records);

            var apps = Deduplicate(records);

            return new AppInventoryResult
            {
                ScanTime = DateTimeOffset.UtcNow,
                Apps = apps
            };
        }

        private static void ScanUninstallKey(
            RegistryHive baseKey,
            RegistryView view,
            string sourceLabel,
            string arch,
            List<InstalledAppRecord> sink)
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(baseKey, view);
                using var uninstall = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");

                if (uninstall == null)
                    return;

                foreach (var subKeyName in uninstall.GetSubKeyNames())
                {
                    using var appKey = uninstall.OpenSubKey(subKeyName);
                    if (appKey == null)
                        continue;

                    var name = (string?)appKey.GetValue("DisplayName");
                    if (string.IsNullOrWhiteSpace(name))
                        continue; // skip hidden/internal entries

                    var displayVersion = (string?)appKey.GetValue("DisplayVersion");
                    var publisher = (string?)appKey.GetValue("Publisher");
                    var installLoc = (string?)appKey.GetValue("InstallLocation");
                    var uninstallStr = (string?)appKey.GetValue("UninstallString");
                    var installDateStr = (string?)appKey.GetValue("InstallDate");

                    bool isSystemComponent = false;
                    try
                    {
                        var sys = appKey.GetValue("SystemComponent");
                        if (sys is int iv && iv != 0)
                            isSystemComponent = true;
                    }
                    catch
                    {
                        // ignore malformed values
                    }

                    DateTimeOffset? installDate = null;
                    if (!string.IsNullOrWhiteSpace(installDateStr) && installDateStr!.Length == 8)
                    {
                        // Typical MSI pattern: yyyyMMdd (but not guaranteed)
                        if (int.TryParse(installDateStr.AsSpan(0, 4), out int year) &&
                            int.TryParse(installDateStr.AsSpan(4, 2), out int month) &&
                            int.TryParse(installDateStr.AsSpan(6, 2), out int day))
                        {
                            try
                            {
                                installDate = new DateTimeOffset(year, month, day, 0, 0, 0, TimeSpan.Zero);
                            }
                            catch
                            {
                                // ignore bad date
                            }
                        }
                    }

                    // Normalized path and existence checks
                    string? normalizedInstallLoc = null;
                    bool installLocationExists = false;

                    try
                    {
                        if (!string.IsNullOrWhiteSpace(installLoc))
                        {
                            var trimmed = installLoc.Trim().Trim('"');
                            if (!string.IsNullOrWhiteSpace(trimmed))
                            {
                                normalizedInstallLoc = Path.GetFullPath(trimmed);
                                installLocationExists =
                                    Directory.Exists(normalizedInstallLoc) ||
                                    File.Exists(normalizedInstallLoc);
                            }
                        }
                    }
                    catch
                    {
                        installLocationExists = false;
                    }

                    bool userWritable = IsUserWritablePath(installLoc);
                    bool missingVersion = string.IsNullOrWhiteSpace(displayVersion);
                    bool lowRepPublisher = IsLowReputationPublisher(publisher);
                    bool hasUninstallEntry = !string.IsNullOrWhiteSpace(uninstallStr);

                    bool isPerUser = sourceLabel.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase);

                    var (category, isNetworkFacing, isRemoteAccess, isVirt, isSecurity) =
                        ClassifyApp(name, publisher);

                    bool isOrphanedInstall =
                        (!hasUninstallEntry && !string.IsNullOrWhiteSpace(normalizedInstallLoc) && installLocationExists) ||
                        (hasUninstallEntry && !string.IsNullOrWhiteSpace(normalizedInstallLoc) && !installLocationExists);

                    int ageInDays = -1;
                    if (installDate.HasValue)
                    {
                        var delta = DateTimeOffset.UtcNow - installDate.Value;
                        if (delta.TotalDays >= 0)
                            ageInDays = (int)delta.TotalDays;
                    }

                    int exposure = 0;
                    int hygiene = 0;
                    var flags = new List<string>();

                    if (userWritable)
                    {
                        exposure += 30;
                        flags.Add("UserWritableLocation");
                    }

                    if (isPerUser)
                    {
                        exposure += 10;
                        flags.Add("PerUserInstall");
                    }

                    if (isNetworkFacing)
                    {
                        exposure += 20;
                        flags.Add("NetworkFacing");
                    }

                    if (isRemoteAccess)
                    {
                        exposure += 20;
                        flags.Add("RemoteAccessTool");
                    }

                    if (isVirt)
                    {
                        exposure += 10;
                        flags.Add("Virtualization");
                    }

                    if (isSecurity)
                    {
                        // Security products are powerful but expected; we keep exposure neutral-ish.
                        exposure += 5;
                        flags.Add("SecurityProduct");
                    }

                    if (missingVersion)
                    {
                        hygiene += 15;
                        flags.Add("MissingVersion");
                    }

                    if (lowRepPublisher)
                    {
                        hygiene += 15;
                        flags.Add("LowReputationPublisher");
                    }

                    if (isOrphanedInstall)
                    {
                        hygiene += 20;
                        flags.Add("OrphanedInstall");
                    }

                    if (ageInDays >= 365 && isNetworkFacing)
                    {
                        hygiene += 10;
                        flags.Add("OldNetworkTool");
                    }

                    if (isSystemComponent)
                    {
                        // usually more benign, reduce score a bit
                        exposure -= 10;
                        hygiene -= 5;
                        flags.Add("SystemComponent");
                    }

                    exposure = Math.Max(0, exposure);
                    hygiene = Math.Max(0, hygiene);

                    int score = exposure + hygiene;
                    if (score < 0) score = 0;
                    if (score > 100) score = 100;

                    sink.Add(new InstalledAppRecord
                    {
                        Name = name.Trim(),
                        Version = displayVersion?.Trim(),
                        Publisher = publisher?.Trim(),
                        InstallLocation = installLoc?.Trim(),
                        InstallDateRaw = installDateStr,
                        InstallDate = installDate,
                        UninstallString = uninstallStr?.Trim(),
                        Source = sourceLabel,
                        Architecture = arch,
                        IsSystemComponent = isSystemComponent,
                        UserWritableLocation = userWritable,
                        MissingVersion = missingVersion,
                        LowReputationPublisher = lowRepPublisher,
                        IsPerUserInstall = isPerUser,
                        IsNetworkFacing = isNetworkFacing,
                        IsRemoteAccessTool = isRemoteAccess,
                        IsVirtualizationOrEmulation = isVirt,
                        IsSecurityProduct = isSecurity,
                        HasUninstallEntry = hasUninstallEntry,
                        InstallLocationExists = installLocationExists,
                        IsOrphanedInstall = isOrphanedInstall,
                        AgeInDays = ageInDays,
                        Category = category,
                        ExposureScore = exposure,
                        HygieneScore = hygiene,
                        Score = score,
                        Flags = string.Join(";", flags.Where(f => !string.IsNullOrWhiteSpace(f)))
                    });
                }
            }
            catch
            {
                // ignore failures for now; could log via your sinkhost later.
            }
        }

        private static List<InstalledAppRecord> Deduplicate(List<InstalledAppRecord> records)
        {
            // Prefer HKLM over HKCU, 64-bit over 32-bit when Name+Version collide.
            // We use a string composite key so we can pass StringComparer.OrdinalIgnoreCase cleanly.
            var groups = records.GroupBy(
                r => $"{r.Name ?? string.Empty}\u001F{(r.Version ?? string.Empty)}",
                StringComparer.OrdinalIgnoreCase);

            var result = new List<InstalledAppRecord>();

            foreach (var g in groups)
            {
                var candidates = g.ToList();
                var best = candidates
                    .OrderByDescending(r => RankSource(r.Source, r.Architecture))
                    .First();

                result.Add(best);
            }

            return result
                .OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
                .ThenBy(r => r.Version ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static int RankSource(string source, string arch)
        {
            // HKLM wins over HKCU, 64 wins over 32; simple scoring.
            int score = 0;
            if (source.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase)) score += 10;
            if (arch.Equals("x64", StringComparison.OrdinalIgnoreCase)) score += 5;
            return score;
        }

        private static bool IsUserWritablePath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            try
            {
                // Trim quotes and whitespace
                var trimmed = path.Trim().Trim('"');

                if (string.IsNullOrWhiteSpace(trimmed))
                    return false;

                var full = Path.GetFullPath(trimmed);

                // System folders that are normally NOT user-writable
                var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                var windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

                if (!string.IsNullOrEmpty(programFiles) &&
                    full.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!string.IsNullOrEmpty(programFilesX86) &&
                    full.StartsWith(programFilesX86, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!string.IsNullOrEmpty(windowsFolder) &&
                    full.StartsWith(windowsFolder, StringComparison.OrdinalIgnoreCase))
                    return false;

                // Folders we DO consider user-writable
                var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                var appDataRoam = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                var temp = Path.GetTempPath();

                if (!string.IsNullOrEmpty(profile) &&
                    full.StartsWith(profile, StringComparison.OrdinalIgnoreCase))
                    return true;

                if (!string.IsNullOrEmpty(localAppData) &&
                    full.StartsWith(localAppData, StringComparison.OrdinalIgnoreCase))
                    return true;

                if (!string.IsNullOrEmpty(appDataRoam) &&
                    full.StartsWith(appDataRoam, StringComparison.OrdinalIgnoreCase))
                    return true;

                if (!string.IsNullOrEmpty(temp) &&
                    full.StartsWith(temp, StringComparison.OrdinalIgnoreCase))
                    return true;

                // Default: treat as non-user-writable
                return false;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsLowReputationPublisher(string? publisher)
        {
            if (string.IsNullOrWhiteSpace(publisher))
                return true; // no publisher at all => suspicious

            var p = publisher.Trim();

            // Big, well-known vendors – treat as "not low rep"
            string[] knownGood =
            {
                "Microsoft", "Microsoft Corporation", "Microsoft LLC",
                "Intel", "Intel Corporation",
                "AMD", "Advanced Micro Devices",
                "NVIDIA", "NVIDIA Corporation",
                "Apple", "Apple Inc.",
                "Lenovo", "Dell", "HP ", "Hewlett-Packard", "Samsung",
                "VMware",
                "Google", "Google LLC",
                "Docker", "Docker Inc.",
                "Dropbox", "Dropbox, Inc.",
                "Oracle", "Oracle Corporation",
                "Cisco", "Cisco Systems, Inc.",
                "JetBrains", "JetBrains s.r.o.",
                "Python Software Foundation",
                "Node.js Foundation", "OpenJS Foundation",
                "The Git Development Community",
                "The Wireshark developer community",
                "Eclipse Adoptium",
                "Raspberry Pi Ltd",
                "Gen Digital Inc.", // Norton/Symantec
                "Opera Software",
                "Autodesk, Inc.",
                "ETH Zürich",
                "GNS3 Technology Inc.",
                "UltiMaker", "Bambulab",
                "The MSYS2 Developers",
                "Kitware",
                "uvnc bvba",
                "Martin Prikryl", // WinSCP
                "Nmap Project"
            };

            foreach (var vendor in knownGood)
            {
                if (p.IndexOf(vendor, StringComparison.OrdinalIgnoreCase) >= 0)
                    return false;
            }

            // Explicit "bad" / generic values
            if (p.Equals("Unknown", StringComparison.OrdinalIgnoreCase)) return true;
            if (p.Equals("N/A", StringComparison.OrdinalIgnoreCase)) return true;
            if (p.Equals("Test", StringComparison.OrdinalIgnoreCase)) return true;
            if (p.Equals("Debug", StringComparison.OrdinalIgnoreCase)) return true;

            // Extremely short publisher names (<= 3 chars) are often garbage
            if (p.Length <= 3)
                return true;

            // Default: assume neutral, not low reputation
            return false;
        }

        private static (string Category, bool IsNetwork, bool IsRemote, bool IsVirt, bool IsSecurity)
            ClassifyApp(string name, string? publisher)
        {
            var sName = name ?? string.Empty;
            var sPub = publisher ?? string.Empty;
            var text = (sName + " " + sPub).ToLowerInvariant();

            bool contains(params string[] patterns)
            {
                foreach (var p in patterns)
                {
                    if (text.Contains(p.ToLowerInvariant()))
                        return true;
                }
                return false;
            }

            bool isBrowser =
                contains("chrome", "opera", "firefox", "edge", "brave", "vivaldi", "browser");

            bool isDevTool =
                contains("visual studio", "vs code", "vscode", "pycharm", "datagrip", "intellij",
                         "node.js", "nodejs", "docker", "git", "python ", "jdk", "java ", "cmake",
                         "msys2", "golang", "rust", "eclipse", "jetbrains");

            bool isRemoteAccess =
                contains("vnc", "ultravnc", "tightvnc", "anydesk", "teamviewer", "logmein",
                         "remote desktop", "remotedesktop", "rdp", "radmin", "splashtop",
                         "pc anywhere", "pcanywhere");

            bool isSecurity =
                contains("antivirus", "anti-virus", "endpoint security", "internet security",
                         "norton", "kaspersky", "defender", "eset", "avast", "bitdefender",
                         "sophos", "mcafee", "crowdstrike", "sentinelone", "trend micro");

            bool isVirtualization =
                contains("vmware", "virtualbox", "virtual box", "hyper-v", "hyperv", "qemu",
                         "docker", "gns3", "eve-ng", "virtual machine", "virtviewer");

            bool isNetworkingOrPacket =
                contains("wireshark", "npcap", "packet tracer", "packettracer", "vpn",
                         "wireguard", "openvpn", "anyconnect");

            bool isNetwork = isBrowser || isRemoteAccess || isNetworkingOrPacket || isVirtualization;

            string category;
            if (isSecurity) category = "Security";
            else if (isRemoteAccess) category = "RemoteAccess";
            else if (isBrowser) category = "Browser";
            else if (isDevTool) category = "DevTool";
            else if (isVirtualization) category = "Virtualization";
            else if (isNetworkingOrPacket) category = "NetworkTool";
            else category = "General";

            return (category, isNetwork, isRemoteAccess, isVirtualization, isSecurity);
        }

        private static (string fileName, string? arguments) SplitCommandLine(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine))
                return (string.Empty, null);

            var s = commandLine.Trim();

            if (s.StartsWith("\"", StringComparison.Ordinal))
            {
                int closingQuote = s.IndexOf('"', 1);
                if (closingQuote > 1)
                {
                    var file = s.Substring(1, closingQuote - 1);
                    var args = s.Length > closingQuote + 1
                        ? s.Substring(closingQuote + 1).Trim()
                        : null;
                    return (file, string.IsNullOrWhiteSpace(args) ? null : args);
                }
            }

            int firstSpace = s.IndexOf(' ');
            if (firstSpace < 0)
            {
                return (s, null);
            }

            var fileName = s.Substring(0, firstSpace);
            var arguments = s.Substring(firstSpace + 1).Trim();
            return (fileName, string.IsNullOrWhiteSpace(arguments) ? null : arguments);
        }

        /// <summary>
        /// Build an uninstall plan for a given app record. Phase 2: your UI can surface this
        /// behind a "Uninstall" button with confirmation and logging.
        /// </summary>
        public UninstallPlan BuildUninstallPlan(InstalledAppRecord app)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));

            if (string.IsNullOrWhiteSpace(app.UninstallString))
            {
                return new UninstallPlan
                {
                    CanUninstall = false,
                    Reason = "No uninstall command registered for this entry.",
                    RawUninstallString = app.UninstallString,
                    Kind = null
                };
            }

            if (app.IsSystemComponent)
            {
                return new UninstallPlan
                {
                    CanUninstall = false,
                    Reason = "Marked as a system component; uninstall from Windows Settings / Programs & Features instead.",
                    RawUninstallString = app.UninstallString,
                    Kind = null
                };
            }

            var raw = app.UninstallString.Trim();

            bool requiresElevation =
                app.Source.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrEmpty(app.InstallLocation) && !IsUserWritablePath(app.InstallLocation));

            var lowerRaw = raw.ToLowerInvariant();

            string kind;
            string fileName;
            string? args;

            if (lowerRaw.Contains("msiexec"))
            {
                kind = "Msi";
                (fileName, args) = SplitCommandLine(raw);
                if (string.IsNullOrWhiteSpace(fileName))
                {
                    // Fallback: let shell parse everything as a single command
                    return new UninstallPlan
                    {
                        CanUninstall = true,
                        Reason = string.Empty,
                        Kind = "Msi",
                        FileName = raw,
                        Arguments = null,
                        UseShellExecute = true,
                        RequiresElevationHint = requiresElevation,
                        RawUninstallString = app.UninstallString
                    };
                }
            }
            else
            {
                kind = "Exe";
                (fileName, args) = SplitCommandLine(raw);
                if (string.IsNullOrWhiteSpace(fileName))
                {
                    return new UninstallPlan
                    {
                        CanUninstall = false,
                        Reason = "Unable to parse uninstall command.",
                        RawUninstallString = app.UninstallString,
                        Kind = null
                    };
                }
            }

            return new UninstallPlan
            {
                CanUninstall = true,
                Reason = string.Empty,
                Kind = kind,
                FileName = fileName,
                Arguments = args,
                UseShellExecute = true,
                RequiresElevationHint = requiresElevation,
                RawUninstallString = app.UninstallString
            };
        }

        /// <summary>
        /// Phase 2 helper: try to launch the uninstall process based on the UninstallString.
        /// UI should confirm with the user before calling this.
        /// </summary>
        public bool TryLaunchUninstall(InstalledAppRecord app, out Exception? error)
        {
            error = null;

            var plan = BuildUninstallPlan(app);
            if (!plan.CanUninstall || string.IsNullOrWhiteSpace(plan.FileName))
            {
                error = new InvalidOperationException(
                    string.IsNullOrEmpty(plan.Reason)
                        ? "This application cannot be uninstalled from here."
                        : plan.Reason);
                return false;
            }

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = plan.FileName!,
                    Arguments = plan.Arguments ?? string.Empty,
                    UseShellExecute = plan.UseShellExecute
                };

                Process.Start(psi);
                return true;
            }
            catch (Exception ex)
            {
                error = ex;
                return false;
            }
        }
    }
}
