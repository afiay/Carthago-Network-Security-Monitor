// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;

namespace Carthago.Analytics.Models
{
    public sealed class BaselineSnapshot
    {
        public string HostId { get; set; } = "";
        public DateTime FirstSeenUtc { get; set; } = DateTime.UtcNow;
        public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdatedUtc { get; set; } = DateTime.UtcNow;
        public int ObservationWindows { get; set; }
        public string Confidence { get; set; } = "Low";
        public int WindowMinutes { get; set; } = 5;

        public double OutboundBytesMean { get; set; }
        public double OutboundBytesStdDev { get; set; }
        public double UniqueDestinationMean { get; set; }
        public double UniqueDestinationStdDev { get; set; }
        public double UniquePortMean { get; set; }
        public double UniquePortStdDev { get; set; }
        public double DnsQueryMean { get; set; }
        public double DnsQueryStdDev { get; set; }
        public double SeverityWeightedAlertMean { get; set; }
        public double SeverityWeightedAlertStdDev { get; set; }

        public List<string> KnownDestinations { get; set; } = new();
        public List<string> KnownPorts { get; set; } = new();
        public List<string> KnownCountries { get; set; } = new();
        public List<string> KnownAsns { get; set; } = new();
        public List<string> KnownJa4Fingerprints { get; set; } = new();
        public List<string> KnownHasshFingerprints { get; set; } = new();
        public List<string> KnownProcesses { get; set; } = new();
    }

    public sealed class BaselineStatus
    {
        public int ObservedHosts { get; set; }
        public int LearningWindowMinutes { get; set; } = 5;
        public DateTime? LastUpdatedUtc { get; set; }
        public string Confidence { get; set; } = "Low";
        public int LowConfidenceHosts { get; set; }
        public int MediumConfidenceHosts { get; set; }
        public int HighConfidenceHosts { get; set; }
    }
}
