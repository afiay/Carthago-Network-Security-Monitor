// SPDX-License-Identifier: MIT
// File: Views/CiscoDeviceEditDialog.xaml.cs

using System.Globalization;
using System.Windows;
using Carthago.Models;

namespace Carthago.Views
{
    public partial class CiscoDeviceEditDialog : Window
    {
        public string DeviceName { get; private set; }
        public string Host { get; private set; }
        public string Role { get; private set; }
        public int SyslogPort { get; private set; }
        public bool DeviceEnabled { get; private set; }

        public CiscoDeviceEditDialog(CiscoDevice device)
        {
            InitializeComponent();

            DeviceName = device.Name;
            Host = device.Host;
            Role = device.Role;
            SyslogPort = device.SyslogPort;
            DeviceEnabled = device.IsEnabled;

            NameBox.Text = DeviceName;
            HostBox.Text = Host;
            RoleBox.Text = Role;
            PortBox.Text = SyslogPort.ToString(CultureInfo.InvariantCulture);
            EnabledCheckBox.IsChecked = DeviceEnabled;
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            var name = NameBox.Text.Trim();
            var host = HostBox.Text.Trim();
            var role = RoleBox.Text.Trim();
            var portText = PortBox.Text.Trim();

            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(host))
            {
                MessageBox.Show(this,
                    "Name and Host/IP are required.",
                    "Cisco Tools",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            if (!int.TryParse(portText, out var port) || port <= 0 || port > 65535)
            {
                MessageBox.Show(this,
                    "Syslog port must be a valid TCP/UDP port (1-65535).",
                    "Cisco Tools",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            DeviceName = name;
            Host = host;
            Role = role;
            SyslogPort = port;
            DeviceEnabled = EnabledCheckBox.IsChecked ?? true;

            DialogResult = true;
            Close();
        }
    }
}
