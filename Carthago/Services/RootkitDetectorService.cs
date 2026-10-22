// SPDX-License-Identifier: MIT
// File: Services/RootkitDetectorService.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Carthago.Services
{
    /// <summary>
    /// Host-integrity helper focused on kernel-mode drivers.
    ///
    /// Design goals:
    /// - Read-only snapshot (no intrusive ops).
    /// - Reasonable heuristics to triage "interesting" drivers:
    ///   * kernel / filesystem drivers
    ///   * running
    ///   * unsigned or unknown publisher
    ///   * located outside standard system driver folders
    ///   * located in user-writable locations
    ///   * "randomish" service names
    ///
    /// This is not a full rootkit detector; it's a cheap scoring/triage engine.
    /// </summary>
    public sealed class RootkitDetectorService
    {
        public sealed class DriverRecord
        {
            /// <summary>WMI Name (service name).</summary>
            public string Name { get; init; } = string.Empty;

            /// <summary>Friendly display name.</summary>
            public string DisplayName { get; init; } = string.Empty;

            /// <summary>Raw WMI PathName, including arguments/prefixes.</summary>
            public string OriginalPath { get; init; } = string.Empty;

            /// <summary>Normalized image path (expanded, cleaned, no args).</summary>
            public string Path { get; init; } = string.Empty;

            /// <summary>WMI State (Running, Stopped, etc.).</summary>
            public string State { get; init; } = string.Empty;

            /// <summary>WMI StartMode (Boot, System, Auto, Manual, Disabled).</summary>
            public string StartMode { get; init; } = string.Empty;

            /// <summary>Raw WMI ServiceType string.</summary>
            public string ServiceTypeRaw { get; init; } = string.Empty;

            /// <summary>True if ServiceType contains "Kernel".</summary>
            public bool IsKernelDriver { get; init; }

            /// <summary>True if ServiceType suggests a filesystem driver.</summary>
            public bool IsFileSystemDriver { get; init; }

            /// <summary>True if State == Running.</summary>
            public bool IsRunning { get; init; }

            /// <summary>True if we could read a code-signing certificate for the file.</summary>
            public bool IsSigned { get; init; }

            /// <summary>Publisher / subject of the signing certificate (best-effort).</summary>
            public string? Publisher { get; init; }

            /// <summary>
            /// True if the image path is outside normal system driver directories,
            /// or otherwise looks unusual given the location.
            /// </summary>
            public bool SuspiciousPath { get; init; }

            /// <summary>
            /// True if the driver is kernel-mode, running, not signed, and not a known-good
            /// vendor/system location.
            /// (We deliberately exclude standard System32\drivers here — see heuristics.)
            /// </summary>
            public bool SuspiciousUnsigned { get; init; }

            /// <summary>
            /// True if the image path is under a user-writable location (user profile, temp, ProgramData, etc.).
            /// </summary>
            public bool UserWritableLocation { get; init; }

            /// <summary>
            /// True if the service name statistically looks "randomish" (letters/digits mix, low vowel ratio).
            /// </summary>
            public bool NameLooksRandom { get; init; }

            /// <summary>
            /// Aggregate numeric score (higher = more interesting / risky).
            /// </summary>
            public int Score { get; init; }

            public enum RiskLevelEnum
            {
                Low = 0,
                Medium = 1,
                High = 2
            }

            /// <summary>
            /// Discrete risk band derived from Score.
            /// </summary>
            public RiskLevelEnum RiskLevel { get; init; }

            /// <summary>
            /// Simple string for UI binding (preserves earlier API expectations).
            /// </summary>
            public string Risk => RiskLevel.ToString();

            /// <summary>
            /// Overall "this is worth attention" flag.
            /// This is what you filter on in the UI.
            /// </summary>
            public bool IsSuspicious { get; init; }

            /// <summary>
            /// Semi-colon separated flags (Kernel;Running;SuspiciousPath;UnsignedKernel;...).
            /// Intended for tooltips / quick debugging.
            /// </summary>
            public string Flags { get; init; } = string.Empty;
        }

        public sealed class RootkitScanResult
        {
            public DateTimeOffset ScanTime { get; init; } = DateTimeOffset.UtcNow;
            public List<DriverRecord> Drivers { get; init; } = new();
        }

        /// <summary>
        /// Perform a best-effort driver enumeration and scoring pass.
        /// Any failures are swallowed; the host integrity UI should never crash because of this.
        /// </summary>
        public RootkitScanResult Scan()
        {
            var result = new RootkitScanResult();

            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, DisplayName, PathName, State, StartMode, ServiceType FROM Win32_SystemDriver");

                foreach (ManagementObject mo in searcher.Get())
                {
                    string name = (string?)(mo["Name"]) ?? string.Empty;
                    string displayName = (string?)(mo["DisplayName"]) ?? name;
                    string rawPath = (string?)(mo["PathName"]) ?? string.Empty;
                    string state = (string?)(mo["State"]) ?? string.Empty;
                    string startMode = (string?)(mo["StartMode"]) ?? string.Empty;
                    string serviceType = (string?)(mo["ServiceType"]) ?? string.Empty;

                    string normalizedPath = NormalizeDriverPath(rawPath);

                    bool isKernel = serviceType.IndexOf("Kernel", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool isFsDriver = serviceType.IndexOf("FileSystemDriver", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool isRunning = state.Equals("Running", StringComparison.OrdinalIgnoreCase);

                    bool underSystemDrivers = IsUnderSystemDriversFolder(normalizedPath);
                    bool userWritableLocation = IsUserWritableLocation(normalizedPath);
                    bool suspiciousPath = IsSuspiciousPath(normalizedPath, userWritableLocation, underSystemDrivers);

                    bool isSigned = TryGetPublisher(normalizedPath, out string? publisher);

                    // IMPORTANT:
                    // We only treat "unsigned running kernel driver" as suspicious if it is
                    // NOT under the standard System32\drivers folder. This removes the noise
                    // you were seeing from normal Windows components where cert parsing fails.
                    bool suspiciousUnsigned =
                        isKernel &&
                        isRunning &&
                        !isSigned &&
                        !underSystemDrivers &&
                        !IsKnownGoodSystemDriver(normalizedPath, publisher);

                    bool nameLooksRandom = NameLooksRandomish(name);

                    int score = ComputeScore(
                        isKernel,
                        isFsDriver,
                        isRunning,
                        suspiciousPath,
                        suspiciousUnsigned,
                        userWritableLocation,
                        nameLooksRandom,
                        startMode,
                        publisher
                    );

                    var riskLevel = ScoreToRisk(score);
                    string flags = BuildFlags(
                        isKernel,
                        isFsDriver,
                        isRunning,
                        suspiciousPath,
                        suspiciousUnsigned,
                        userWritableLocation,
                        nameLooksRandom,
                        isSigned,
                        underSystemDrivers);

                    // This is the master "show in suspicious grid" flag.
                    // You can tweak the thresholds if you want more/less noise.
                    bool isSuspiciousOverall =
                        suspiciousUnsigned ||
                        (userWritableLocation && isKernel) ||
                        (suspiciousPath && !underSystemDrivers) ||
                        (nameLooksRandom && riskLevel != DriverRecord.RiskLevelEnum.Low) ||
                        (riskLevel == DriverRecord.RiskLevelEnum.High);

                    result.Drivers.Add(new DriverRecord
                    {
                        Name = name,
                        DisplayName = displayName,
                        OriginalPath = rawPath,
                        Path = normalizedPath,
                        State = state,
                        StartMode = startMode,
                        ServiceTypeRaw = serviceType,
                        IsKernelDriver = isKernel,
                        IsFileSystemDriver = isFsDriver,
                        IsRunning = isRunning,
                        IsSigned = isSigned,
                        Publisher = publisher,
                        SuspiciousPath = suspiciousPath,
                        SuspiciousUnsigned = suspiciousUnsigned,
                        UserWritableLocation = userWritableLocation,
                        NameLooksRandom = nameLooksRandom,
                        Score = score,
                        RiskLevel = riskLevel,
                        IsSuspicious = isSuspiciousOverall,
                        Flags = flags
                    });
                }
            }
            catch
            {
                // Swallow everything; UI is allowed to degrade but not crash.
            }

            // Sort by score descending so the UI can just bind and show "most interesting" at the top.
            try
            {
                result.Drivers.Sort((a, b) => b.Score.CompareTo(a.Score));
            }
            catch
            {
                // Ignore sort failures; list is still usable.
            }

            return result;
        }

        // ======== Path & environment helpers ========

        private static string NormalizeDriverPath(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return string.Empty;

            var txt = raw.Trim().Trim('"');

            // NT-style prefix: \??\C:\Windows\...
            const string ntPrefix = @"\??\";
            if (txt.StartsWith(ntPrefix, StringComparison.OrdinalIgnoreCase))
                txt = txt.Substring(ntPrefix.Length);

            // Strip arguments after .sys / .exe
            int sysIdx = txt.IndexOf(".sys", StringComparison.OrdinalIgnoreCase);
            int exeIdx = txt.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            int cutIdx = Math.Max(sysIdx, exeIdx);
            if (cutIdx > 0)
                txt = txt.Substring(0, cutIdx + 4);

            // Expand \SystemRoot\...
            if (txt.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            {
                var root = Environment.GetEnvironmentVariable("SystemRoot");
                if (!string.IsNullOrEmpty(root))
                    txt = Path.Combine(root, txt.Substring(@"\SystemRoot\".Length));
            }

            // Expand environment variables such as %SystemRoot%, %windir%, etc.
            txt = ExpandEnvVarsSafe(txt);

            return txt;
        }

        private static string ExpandEnvVarsSafe(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path))
                    return path;

                return Environment.ExpandEnvironmentVariables(path);
            }
            catch
            {
                return path;
            }
        }

        private static bool IsUnder(string path, string? root)
        {
            if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(root))
                return false;

            try
            {
                string fullPath = Path.GetFullPath(path)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string fullRoot = Path.GetFullPath(root)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                return fullPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private static bool IsUnderSystemDriversFolder(string path)
        {
            var systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
            var driversDir = Path.Combine(systemRoot, "System32", "drivers");
            return IsUnder(path, driversDir);
        }

        private static bool IsUserWritableLocation(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            try
            {
                string full = Path.GetFullPath(path);

                string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                string tempDir = Path.GetTempPath();
                string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

                if (IsUnder(full, userProfile)) return true;
                if (IsUnder(full, tempDir)) return true;
                if (IsUnder(full, programData)) return true;

                // Generic "Users" root – many user profiles live here.
                var driveRoot = Path.GetPathRoot(full);
                if (!string.IsNullOrEmpty(driveRoot))
                {
                    var usersRoot = Path.Combine(driveRoot, "Users");
                    if (IsUnder(full, usersRoot)) return true;
                }
            }
            catch
            {
                // If we can't reason about it, don't infer it's user-writable.
            }

            return false;
        }

        private static bool IsSuspiciousPath(string path, bool userWritableLocation, bool underSystemDrivers)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            try
            {
                string full = Path.GetFullPath(path);
                string systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";

                // If it's in the canonical drivers folder and *not* user-writable, treat as non-suspicious path.
                if (underSystemDrivers && !userWritableLocation)
                    return false;

                // Outside system root + user-writable → suspicious.
                if (userWritableLocation)
                    return true;

                // Outside %SystemRoot% at all → mildly suspicious.
                if (!full.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch
            {
                // On failure, use userWritableLocation as a conservative indicator.
                return userWritableLocation;
            }

            return false;
        }

        // ======== Signature & vendor heuristics ========

        private static bool TryGetPublisher(string path, out string? publisher)
        {
            publisher = null;

            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                    return false;

                using var baseCert = X509Certificate.CreateFromSignedFile(path);
                using var cert = new X509Certificate2(baseCert);

                // Prefer subject simple name; fall back to issuer.
                publisher = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                if (string.IsNullOrWhiteSpace(publisher))
                    publisher = cert.Issuer;

                return !string.IsNullOrWhiteSpace(publisher);
            }
            catch
            {
                return false;
            }
        }

        private static bool IsKnownGoodSystemDriver(string path, string? publisher)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
            string driversDir = Path.Combine(systemRoot, "System32", "drivers");

            bool underDrivers = IsUnder(path, driversDir);
            if (!underDrivers)
                return false;

            if (publisher is null)
                return false;

            // Core platform vendors in the canonical driver folder → treat as "known good".
            if (publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)) return true;
            if (publisher.Contains("Intel", StringComparison.OrdinalIgnoreCase)) return true;
            if (publisher.Contains("Lenovo", StringComparison.OrdinalIgnoreCase)) return true;
            if (publisher.Contains("Realtek", StringComparison.OrdinalIgnoreCase)) return true;
            if (publisher.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase)) return true;
            if (publisher.Contains("AMD", StringComparison.OrdinalIgnoreCase)) return true;

            return false;
        }

        // ======== Name & scoring heuristics ========

        private static bool NameLooksRandomish(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;

            string simplified = name.Trim().Trim('_');
            if (simplified.Length < 6)
                return false;

            int letters = 0, digits = 0;
            foreach (char c in simplified)
            {
                if (char.IsLetter(c)) letters++;
                else if (char.IsDigit(c)) digits++;
            }

            if (letters + digits < 4)
                return false;

            double digitRatio = digits / (double)(letters + digits);
            double letterRatio = letters / (double)(letters + digits);

            int vowels = 0;
            foreach (char c in simplified.ToLowerInvariant())
            {
                if ("aeiou".IndexOf(c) >= 0) vowels++;
            }

            double vowelRatio = vowels / (double)Math.Max(letters, 1);

            // Very naive "randomish" heuristic:
            // - substantial mix of letters/digits
            // - few vowels (e.g., "xkqpr9")
            if (digitRatio >= 0.3 && digitRatio <= 0.7 && letterRatio > 0.2 && vowelRatio < 0.2)
                return true;

            return false;
        }

        private static int ComputeScore(
            bool isKernel,
            bool isFsDriver,
            bool isRunning,
            bool suspiciousPath,
            bool suspiciousUnsigned,
            bool userWritableLocation,
            bool nameLooksRandom,
            string startMode,
            string? publisher)
        {
            int score = 0;

            if (isKernel) score += 15;
            if (isFsDriver) score += 10;

            if (isRunning) score += 10;

            if (suspiciousPath) score += 25;
            if (userWritableLocation) score += 20;
            if (suspiciousUnsigned) score += 30;

            if (nameLooksRandom) score += 10;

            if (!string.IsNullOrWhiteSpace(startMode))
            {
                if (startMode.Equals("Boot", StringComparison.OrdinalIgnoreCase)) score += 12;
                else if (startMode.Equals("System", StringComparison.OrdinalIgnoreCase)) score += 8;
                else if (startMode.Equals("Auto", StringComparison.OrdinalIgnoreCase)) score += 5;
            }

            if (!string.IsNullOrWhiteSpace(publisher))
            {
                if (publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)) score -= 25;
                else if (publisher.Contains("Intel", StringComparison.OrdinalIgnoreCase)) score -= 10;
                else if (publisher.Contains("Lenovo", StringComparison.OrdinalIgnoreCase)) score -= 8;
                else if (publisher.Contains("Realtek", StringComparison.OrdinalIgnoreCase)) score -= 8;
            }
            else
            {
                // Unknown publisher → small nudge upwards.
                score += 5;
            }

            if (score < 0) score = 0;
            return score;
        }

        private static DriverRecord.RiskLevelEnum ScoreToRisk(int score)
        {
            if (score >= 70) return DriverRecord.RiskLevelEnum.High;
            if (score >= 35) return DriverRecord.RiskLevelEnum.Medium;
            return DriverRecord.RiskLevelEnum.Low;
        }

        private static string BuildFlags(
            bool isKernel,
            bool isFsDriver,
            bool isRunning,
            bool suspiciousPath,
            bool suspiciousUnsigned,
            bool userWritableLocation,
            bool nameLooksRandom,
            bool isSigned,
            bool underSystemDrivers)
        {
            var sb = new StringBuilder();

            if (isKernel) sb.Append("Kernel;");
            if (isFsDriver) sb.Append("FS;");
            if (isRunning) sb.Append("Running;");
            if (underSystemDrivers) sb.Append("SystemDrivers;");
            if (suspiciousPath) sb.Append("SuspiciousPath;");
            if (userWritableLocation) sb.Append("UserWritable;");
            if (suspiciousUnsigned) sb.Append("UnsignedKernel;");
            if (nameLooksRandom) sb.Append("WeirdName;");
            if (!isSigned) sb.Append("NoSignature;");

            return sb.ToString().TrimEnd(';');
        }
    }
}
