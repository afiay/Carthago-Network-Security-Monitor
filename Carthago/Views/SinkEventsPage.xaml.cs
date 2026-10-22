// SPDX-License-Identifier: MIT
// File: Views/SinkEventsPage.xaml.cs
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Controls;
using System.Windows.Threading;
using Carthago.Models;
using Carthago.Sinks;

namespace Carthago.Views
{
    public partial class SinkEventsPage : Page, INotifyPropertyChanged
    {
        private readonly SinkHost _host;
        private readonly Dispatcher _ui;

        // keep concrete delegate instances so we can unsubscribe cleanly
        private Action<string, DetectionEvent, DateTime>? _onEmitted;
        private Action<string, DetectionEvent, Exception, DateTime>? _onFailed;

        private bool _paused;

        public ObservableCollection<EmittedRow> Emitted { get; } = new();
        public ObservableCollection<FailureRow> Failures { get; } = new();

        public event PropertyChangedEventHandler? PropertyChanged;

        public bool Paused
        {
            get => _paused;
            set { _paused = value; OnPropertyChanged(); }
        }

        public SinkEventsPage(SinkHost host)
        {
            InitializeComponent();

            _host = host ?? throw new ArgumentNullException(nameof(host));
            _ui = Dispatcher;
            DataContext = this;

            // explicit handlers to avoid method-group ambiguity
            _onEmitted = (sink, e, utc) => HandleEmitted(sink, e, utc);
            _onFailed = (sink, e, ex, utc) => HandleFailed(sink, e, ex, utc);

            // defensive: detach if already attached, then attach
            _host.SinkEmitted -= _onEmitted;
            _host.SinkFailed -= _onFailed;
            _host.SinkEmitted += _onEmitted;
            _host.SinkFailed += _onFailed;

            // clean up when page goes away
            this.Unloaded += (_, __) =>
            {
                try { if (_onEmitted is not null) _host.SinkEmitted -= _onEmitted; } catch { }
                try { if (_onFailed is not null) _host.SinkFailed -= _onFailed; } catch { }
            };

            // optional UI toggles (safe if not present in XAML)
            try
            {
                PauseToggle.Checked += (_, __) => Paused = true;
                PauseToggle.Unchecked += (_, __) => Paused = false;
            }
            catch { /* PauseToggle not in XAML; ignore */ }
        }

        // -------- handlers (match SinkHost tuple events) --------

        private void HandleEmitted(string sink, DetectionEvent e, DateTime utc)
        {
            if (Paused) return;

            var row = EmittedRow.From(sink, e, utc);
            _ui.BeginInvoke(DispatcherPriority.Background, new Action(() =>
            {
                Emitted.Insert(0, row);
                if (Emitted.Count > 5000) Emitted.RemoveAt(Emitted.Count - 1);
            }));
        }

        private void HandleFailed(string sink, DetectionEvent e, Exception ex, DateTime utc)
        {
            if (Paused) return;

            var row = FailureRow.From(sink, e, ex, utc);
            _ui.BeginInvoke(DispatcherPriority.Background, new Action(() =>
            {
                Failures.Insert(0, row);
                if (Failures.Count > 2000) Failures.RemoveAt(Failures.Count - 1);
            }));
        }

        private void Clear_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            Emitted.Clear();
            Failures.Clear();
        }

        private void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public sealed class EmittedRow
    {
        public DateTime TimestampUtc { get; init; }
        public string Sink { get; init; } = "";
        public SeverityLevel Severity { get; init; }
        public string? RuleId { get; init; }
        public string? SourceIp { get; init; }
        public string? DestinationIp { get; init; }
        public int? DestinationPort { get; init; }
        public string? Protocol { get; init; }
        public string Description { get; init; } = "";

        public static EmittedRow From(string sink, DetectionEvent e, DateTime utc) =>
            new()
            {
                TimestampUtc = utc,
                Sink = sink,
                Severity = e.Severity,
                RuleId = e.RuleId,
                SourceIp = e.SourceIp,
                DestinationIp = e.DestinationIp,
                DestinationPort = e.DestinationPort,
                Protocol = e.Protocol,
                Description = e.Description ?? ""
            };
    }

    public sealed class FailureRow
    {
        public DateTime TimestampUtc { get; init; }
        public string Sink { get; init; } = "";
        public SeverityLevel Severity { get; init; }
        public string? RuleId { get; init; }
        public string? SourceIp { get; init; }
        public string? DestinationIp { get; init; }
        public int? DestinationPort { get; init; }
        public string? Protocol { get; init; }
        public string Error { get; init; } = "";

        public static FailureRow From(string sink, DetectionEvent e, Exception ex, DateTime utc) =>
            new()
            {
                TimestampUtc = utc,
                Sink = sink,
                Severity = e.Severity,
                RuleId = e.RuleId,
                SourceIp = e.SourceIp,
                DestinationIp = e.DestinationIp,
                DestinationPort = e.DestinationPort,
                Protocol = e.Protocol,
                Error = ex.Message
            };
    }
}
