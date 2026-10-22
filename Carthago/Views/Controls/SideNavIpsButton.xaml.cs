// SPDX-License-Identifier: MIT
// File: Views/Controls/SideNavIpsButton.xaml.cs
using System.Windows;
using System.Windows.Controls;

namespace Carthago.Views.Controls
{
    public partial class SideNavIpsButton : UserControl
    {
        public static readonly RoutedEvent NavigateIpsRequestedEvent =
            EventManager.RegisterRoutedEvent("NavigateIpsRequested", RoutingStrategy.Bubble, typeof(RoutedEventHandler), typeof(SideNavIpsButton));

        public event RoutedEventHandler NavigateIpsRequested
        {
            add { AddHandler(NavigateIpsRequestedEvent, value); }
            remove { RemoveHandler(NavigateIpsRequestedEvent, value); }
        }

        public SideNavIpsButton()
        {
            InitializeComponent();
            Btn.Click += (_, __) => RaiseEvent(new RoutedEventArgs(NavigateIpsRequestedEvent));
        }
    }
}
