// SPDX-License-Identifier: MIT
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Carthago.Controls
{
    public partial class RiskScoreGauge : UserControl
    {
        public static readonly DependencyProperty ScoreProperty =
            DependencyProperty.Register(nameof(Score), typeof(int), typeof(RiskScoreGauge), new PropertyMetadata(0));

        public static readonly DependencyProperty SeverityProperty =
            DependencyProperty.Register(nameof(Severity), typeof(string), typeof(RiskScoreGauge), new PropertyMetadata("Low", OnVisualPropertyChanged));

        public static readonly DependencyProperty CaptionProperty =
            DependencyProperty.Register(nameof(Caption), typeof(string), typeof(RiskScoreGauge), new PropertyMetadata("RISK SCORE"));

        public static readonly DependencyProperty StatusTextProperty =
            DependencyProperty.Register(nameof(StatusText), typeof(string), typeof(RiskScoreGauge), new PropertyMetadata(string.Empty));

        public static readonly DependencyProperty GaugeSizeProperty =
            DependencyProperty.Register(nameof(GaugeSize), typeof(double), typeof(RiskScoreGauge), new PropertyMetadata(112d));

        public static readonly DependencyProperty AccentBrushProperty =
            DependencyProperty.Register(nameof(AccentBrush), typeof(Brush), typeof(RiskScoreGauge), new PropertyMetadata(Brushes.SlateGray));

        public RiskScoreGauge()
        {
            InitializeComponent();
            UpdateVisuals();
        }

        public int Score
        {
            get => (int)GetValue(ScoreProperty);
            set => SetValue(ScoreProperty, value);
        }

        public string Severity
        {
            get => (string)GetValue(SeverityProperty);
            set => SetValue(SeverityProperty, value);
        }

        public string Caption
        {
            get => (string)GetValue(CaptionProperty);
            set => SetValue(CaptionProperty, value);
        }

        public string StatusText
        {
            get => string.IsNullOrWhiteSpace((string)GetValue(StatusTextProperty))
                ? Severity
                : (string)GetValue(StatusTextProperty);
            set => SetValue(StatusTextProperty, value);
        }

        public double GaugeSize
        {
            get => (double)GetValue(GaugeSizeProperty);
            set => SetValue(GaugeSizeProperty, value);
        }

        public Brush AccentBrush
        {
            get => (Brush)GetValue(AccentBrushProperty);
            set => SetValue(AccentBrushProperty, value);
        }

        private static void OnVisualPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            if (d is RiskScoreGauge gauge)
                gauge.UpdateVisuals();
        }

        private void UpdateVisuals()
        {
            AccentBrush = ResolveSeverityBrush(Severity);
            if (AccentRing != null)
                AccentRing.Stroke = AccentBrush;
        }

        private static Brush ResolveSeverityBrush(string? severity)
        {
            var key = severity?.ToLowerInvariant() switch
            {
                "critical" => "SeverityCriticalBrush",
                "high" => "SeverityHighBrush",
                "medium" => "SeverityMediumBrush",
                "low" => "SeverityLowBrush",
                _ => "SeverityUnknownBrush"
            };

            return Application.Current.TryFindResource(key) as Brush ?? Brushes.SlateGray;
        }
    }
}
