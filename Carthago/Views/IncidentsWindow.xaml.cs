// SPDX-License-Identifier: MIT
// File: Views/IncidentsWindow.xaml.cs
using System.Windows;
using Carthago.Sinks;

namespace Carthago.Views
{
    public partial class IncidentsWindow : Window
    {
        public IncidentsWindow(SinkHost sinkHost)
        {
            InitializeComponent();
            this.Content = new IncidentsPage(sinkHost);
        }
    }
}
