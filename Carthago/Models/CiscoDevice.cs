// SPDX-License-Identifier: MIT
// File: Models/CiscoDevice.cs

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Carthago.Models
{
    /// <summary>
    /// Cisco device tracked by the Cisco tools panel.
    /// Now includes a simple health model (0–100 + Good/Warning/Critical)
    /// used by the UI to colorize rows and topology nodes.
    /// </summary>
    public sealed class CiscoDevice : INotifyPropertyChanged
    {
        private string _name = string.Empty;
        private string _host = string.Empty;
        private int _syslogPort = 5514;

        private string _role = string.Empty;

        private bool _isEnabled = true;
        private bool _isOnline;
        private DateTime? _lastSeenUtc;

        private string? _lastEventSeverityName;
        private string? _lastEventCategory;
        private string? _lastEventSummary;

        private string? _iosVersion;
        private DateTime? _iosVersionLastSeenUtc;
        private string _iosStatus = "Unknown";

        private double _topologyX;
        private double _topologyY;

        private string? _sshUsername;
        private string? _sshPassword;
        private string? _sshEnablePassword;

        // NEW: health model
        private int _healthScore = 100;
        private string _healthState = "Unknown";

        // NEW: tiny health history for sparklines (last N points)
        private readonly ObservableCollection<int> _healthHistory = new();
        private const int MaxHealthHistoryPoints = 32;
        public ReadOnlyObservableCollection<int> HealthHistory { get; }

        public CiscoDevice()
        {
            HealthHistory = new ReadOnlyObservableCollection<int>(_healthHistory);
            RecomputeHealth();
        }

        // --------- identity / config ---------

        public string Name
        {
            get => _name;
            set => SetField(ref _name, value);
        }

        public string Host
        {
            get => _host;
            set => SetField(ref _host, value);
        }

        public int SyslogPort
        {
            get => _syslogPort;
            set => SetField(ref _syslogPort, value);
        }

        public string Role
        {
            get => _role;
            set => SetField(ref _role, value);
        }

        /// <summary>
        /// Whether this device is considered in the health calculations.
        /// Disabled devices still exist in the topology but are treated as
        /// lower priority and penalized a bit.
        /// </summary>
        public bool IsEnabled
        {
            get => _isEnabled;
            set
            {
                if (SetField(ref _isEnabled, value))
                    RecomputeHealth();
            }
        }

        // --------- last seen / state ---------

        /// <summary>
        /// Last time we saw any signal from this device (syslog, SNMP, etc) in UTC.
        /// </summary>
        public DateTime? LastSeenUtc
        {
            get => _lastSeenUtc;
            set
            {
                if (SetField(ref _lastSeenUtc, value))
                    RecomputeHealth();
            }
        }

        /// <summary>
        /// Whether this device is currently considered online.
        /// </summary>
        public bool IsOnline
        {
            get => _isOnline;
            set
            {
                if (SetField(ref _isOnline, value))
                    RecomputeHealth();
            }
        }

        /// <summary>
        /// Last syslog severity name we saw (e.g. "Warning", "Critical").
        /// </summary>
        public string? LastEventSeverityName
        {
            get => _lastEventSeverityName;
            set
            {
                if (SetField(ref _lastEventSeverityName, value))
                    RecomputeHealth();
            }
        }

        /// <summary>
        /// Last syslog category we saw (e.g. "Interface", "Security", etc).
        /// </summary>
        public string? LastEventCategory
        {
            get => _lastEventCategory;
            set => SetField(ref _lastEventCategory, value);
        }

        /// <summary>
        /// Short text summary of the last interesting event.
        /// </summary>
        public string? LastEventSummary
        {
            get => _lastEventSummary;
            set => SetField(ref _lastEventSummary, value);
        }

        // --------- IOS version ---------

        public string? IosVersion
        {
            get => _iosVersion;
            set => SetField(ref _iosVersion, value);
        }

        public DateTime? IosVersionLastSeenUtc
        {
            get => _iosVersionLastSeenUtc;
            set => SetField(ref _iosVersionLastSeenUtc, value);
        }

        /// <summary>
        /// High-level status used by the UI (e.g., "Up to date", "Update recommended", "Unknown").
        /// </summary>
        public string IosStatus
        {
            get => _iosStatus;
            set
            {
                if (SetField(ref _iosStatus, value))
                    RecomputeHealth();
            }
        }

        // --------- topology layout ---------

        /// <summary>
        /// X coordinate (in arbitrary canvas units) used by the topology view.
        /// </summary>
        public double TopologyX
        {
            get => _topologyX;
            set => SetField(ref _topologyX, value);
        }

        /// <summary>
        /// Y coordinate (in arbitrary canvas units) used by the topology view.
        /// </summary>
        public double TopologyY
        {
            get => _topologyY;
            set => SetField(ref _topologyY, value);
        }

        // --------- SSH credentials (for version / config fetch) ---------

        public string? SshUsername
        {
            get => _sshUsername;
            set => SetField(ref _sshUsername, value);
        }

        public string? SshPassword
        {
            get => _sshPassword;
            set => SetField(ref _sshPassword, value);
        }

        public string? SshEnablePassword
        {
            get => _sshEnablePassword;
            set => SetField(ref _sshEnablePassword, value);
        }

        // --------- health score ---------

        /// <summary>
        /// Computed health score from 0–100 used by the UI.
        /// </summary>
        public int HealthScore
        {
            get => _healthScore;
            private set => SetField(ref _healthScore, value);
        }

        /// <summary>
        /// Coarse health bucket for styling: "Good", "Warning", "Critical", "Unknown".
        /// </summary>
        public string HealthState
        {
            get => _healthState;
            private set => SetField(ref _healthState, value);
        }

        private void RecomputeHealth()
        {
            int score = 100;

            // Disabled devices get a small penalty
            if (!IsEnabled)
                score -= 20;

            // Online/offline signal
            if (!IsOnline)
                score -= 30;

            // IOS status impact
            var ios = _iosStatus ?? string.Empty;
            if (ios.Equals("Update recommended", StringComparison.OrdinalIgnoreCase))
            {
                score -= 20;
            }
            else if (ios.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            {
                score -= 5;
            }
            else if (ios.IndexOf("end-of-life", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     ios.IndexOf("eol", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                score -= 30;
            }

            // Last syslog severity impact
            var sev = _lastEventSeverityName ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(sev))
            {
                if (sev.IndexOf("Emergency", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    sev.IndexOf("Alert", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    sev.IndexOf("Critical", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    score -= 35;
                }
                else if (sev.IndexOf("Error", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    score -= 25;
                }
                else if (sev.IndexOf("Warning", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    score -= 10;
                }
            }

            if (score < 0) score = 0;
            if (score > 100) score = 100;

            string state;
            if (score >= 80) state = "Good";
            else if (score >= 50) state = "Warning";
            else state = "Critical";

            HealthScore = score;
            HealthState = state;

            AppendHealthHistory(score);
        }

        private void AppendHealthHistory(int score)
        {
            if (score < 0) score = 0;
            if (score > 100) score = 100;

            _healthHistory.Add(score);
            while (_healthHistory.Count > MaxHealthHistoryPoints)
                _healthHistory.RemoveAt(0);

            OnPropertyChanged(nameof(HealthHistory));
        }

        // --------- INotifyPropertyChanged ---------

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

        private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value))
                return false;

            field = value;
            OnPropertyChanged(propertyName);
            return true;
        }
    }
}
