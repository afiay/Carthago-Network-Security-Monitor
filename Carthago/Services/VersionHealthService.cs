// SPDX-License-Identifier: MIT
// File: Services/VersionHealthService.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Carthago.Services
{
    /// <summary>
    /// Simple component-version health checker.
    /// Today:
    ///  - Windows build
    ///  - .NET runtime
    ///  - Carthago assembly version
    ///
    /// Recommended versions are hard-coded baselines you can tune.
    /// </summary>
    public sealed class VersionHealthService
    {
        public sealed class VersionCheckResult
        {
            public string Component { get; init; } = string.Empty;
            public string CurrentVersion { get; init; } = string.Empty;
            public string RecommendedVersion { get; init; } = string.Empty;
            public bool IsOutdated { get; init; }
            public string? UpdateHint { get; init; }
            public string? UpdateLink { get; init; }
        }

        // 🔮 Baselines – tune these for your environment
        private readonly Version _minNet = new(8, 0, 0, 0);
        private readonly Version _minWindows = new(10, 0, 19044, 0); // Win10 21H2+
        private readonly Version _minCarthago = new(0, 1, 0, 0);       // example floor

        public IReadOnlyList<VersionCheckResult> GetChecks()
        {
            var list = new List<VersionCheckResult>();

            // .NET runtime
            var frameworkDesc = RuntimeInformation.FrameworkDescription; // ".NET 8.0.0"
            var netVersion = ParseVersionFromString(frameworkDesc, Environment.Version);

            list.Add(new VersionCheckResult
            {
                Component = ".NET Runtime",
                CurrentVersion = frameworkDesc,
                RecommendedVersion = $">= {_minNet}",
                IsOutdated = netVersion < _minNet,
                UpdateHint = "Install the latest .NET 8 runtime from Microsoft.",
                UpdateLink = "https://dotnet.microsoft.com/en-us/download"
            });

            // Windows
            var os = Environment.OSVersion;
            list.Add(new VersionCheckResult
            {
                Component = "Windows",
                CurrentVersion = os.VersionString,
                RecommendedVersion = ">= 10.0.19044 (Windows 10 21H2)",
                IsOutdated = os.Version < _minWindows,
                UpdateHint = "Run Windows Update and install the latest feature update.",
                UpdateLink = "ms-settings:windowsupdate"
            });

            // Carthago itself
            var asmVersion = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0);
            list.Add(new VersionCheckResult
            {
                Component = "Carthago",
                CurrentVersion = asmVersion.ToString(),
                RecommendedVersion = $">= {_minCarthago}",
                IsOutdated = asmVersion < _minCarthago,
                UpdateHint = "Deploy the latest Carthago build.",
                UpdateLink = null // you probably distribute this internally
            });

            return list;
        }

        private static Version ParseVersionFromString(string input, Version fallback)
        {
            if (string.IsNullOrWhiteSpace(input))
                return fallback;

            foreach (var token in input.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (Version.TryParse(token.TrimStart('v', 'V'), out var v))
                    return v;
            }

            return fallback;
        }

        public void OpenUpdateLink(VersionCheckResult res)
        {
            if (string.IsNullOrWhiteSpace(res.UpdateLink))
                return;

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = res.UpdateLink,
                    UseShellExecute = true
                };

                Process.Start(psi);
            }
            catch
            {
                // ignore, or route into your telemetry/sink
            }
        }
    }
}
