// SPDX-License-Identifier: MIT
// File: Views/IncidentsWindow.xaml.cs
using System.Windows;
using Carthago.Sinks;

namespace Carthago.Views
{
    public partial class IncidentsWindow : Window
    {
        private readonly IncidentsPage _page;

        public IncidentsWindow(SinkHost sinkHost)
        {
            InitializeComponent();
            _page = new IncidentsPage(sinkHost);
            Content = _page;
            SourceInitialized += (_, _) => ApplyWindowLayout();
            Loaded += (_, _) => ApplyWindowLayout();
            SizeChanged += (_, _) => ApplyWindowLayout();
        }

        private void ApplyWindowLayout()
        {
            var width = ActualWidth > 0 ? ActualWidth : Width;
            _page.ApplyResponsiveLayout(ResponsiveLayout.Resolve(width));

            const double preferredMinWidth = 520;
            const double preferredMinHeight = 400;
            var workArea = SystemParameters.WorkArea;
            var ownerWidth = Owner?.ActualWidth > 0 ? Owner.ActualWidth : workArea.Width;
            var ownerHeight = Owner?.ActualHeight > 0 ? Owner.ActualHeight : workArea.Height;
            var availableWidth = System.Math.Min(ownerWidth, workArea.Width);
            var availableHeight = System.Math.Min(ownerHeight, workArea.Height);
            var maximumWidth = availableWidth * 0.94;
            var maximumHeight = availableHeight * 0.94;

            MinWidth = System.Math.Min(preferredMinWidth, maximumWidth);
            MinHeight = System.Math.Min(preferredMinHeight, maximumHeight);
            MaxWidth = maximumWidth;
            MaxHeight = maximumHeight;
            Width = ResponsiveLayout.ConstrainDimension(Width, preferredMinWidth, availableWidth, 0.94);
            Height = ResponsiveLayout.ConstrainDimension(Height, preferredMinHeight, availableHeight, 0.94);
        }
    }
}
