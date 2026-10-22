// SPDX-License-Identifier: MIT
// File: Views/CiscoCredentialsDialog.xaml.cs

using System.Windows;

namespace Carthago.Views
{
    public partial class CiscoCredentialsDialog : Window
    {
        public string Username { get; private set; } = string.Empty;
        public string Password { get; private set; } = string.Empty;
        public string EnablePassword { get; private set; } = string.Empty;

        public CiscoCredentialsDialog(string? username, string? password, string? enablePassword)
        {
            InitializeComponent();

            UsernameBox.Text = username ?? string.Empty;
            PasswordBox.Password = password ?? string.Empty;
            EnablePasswordBox.Password = enablePassword ?? string.Empty;
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            Username = UsernameBox.Text.Trim();
            Password = PasswordBox.Password;
            EnablePassword = EnablePasswordBox.Password;

            DialogResult = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
