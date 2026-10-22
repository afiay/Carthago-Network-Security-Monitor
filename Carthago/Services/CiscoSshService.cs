// SPDX-License-Identifier: MIT
// File: Services/Cisco/CiscoSshService.cs

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Renci.SshNet;

namespace Carthago.Services.Cisco
{
    /// <summary>
    /// Very small helper that connects to a Cisco device over SSH
    /// and issues a "reload" command, including the interactive
    /// confirmation prompts IOS shows.
    /// </summary>
    public sealed class CiscoSshService
    {
        /// <summary>
        /// Reload the given device via SSH (vty). Throws if we cannot
        /// connect, authenticate, or see the expected reload prompts.
        /// </summary>
        public Task ReloadAsync(CiscoDevice device, CancellationToken cancellationToken = default)
        {
            if (device == null) throw new ArgumentNullException(nameof(device));
            if (string.IsNullOrWhiteSpace(device.Host))
                throw new ArgumentException("Device.Host must be set for SSH reload", nameof(device));

            if (string.IsNullOrWhiteSpace(device.SshUsername))
                throw new InvalidOperationException("SSH username is not set on this device.");
            if (string.IsNullOrWhiteSpace(device.SshPassword))
                throw new InvalidOperationException("SSH password is not set on this device.");

            // Use the enable password if explicitly set, otherwise reuse the login password.
            var enablePassword = string.IsNullOrWhiteSpace(device.SshEnablePassword)
                ? device.SshPassword
                : device.SshEnablePassword;

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Renci.SshNet supports the old Cisco algorithms (group14, aes*-cbc, hmac-sha1),
                // so we can usually just use the basic constructor.
                using var client = new SshClient(device.Host, 22, device.SshUsername, device.SshPassword);

                try
                {
                    client.Connect();
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException(
                        $"SSH connect failed to {device.Host}: {ex.Message}", ex);
                }

                if (!client.IsConnected)
                    throw new InvalidOperationException("SSH client could not connect to the device.");

                using var shell = client.CreateShellStream(
                    "cisco-reload", 80, 24, 800, 600, 4096);

                var transcript = new StringBuilder();

                void WriteLine(string text)
                {
                    shell.WriteLine(text);
                    shell.Flush();
                }

                string ReadSome(int waitMs = 200, int maxMs = 5000)
                {
                    var end = DateTime.UtcNow.AddMilliseconds(maxMs);
                    var local = new StringBuilder();

                    while (DateTime.UtcNow < end)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        if (shell.DataAvailable)
                        {
                            var chunk = shell.Read();
                            if (!string.IsNullOrEmpty(chunk))
                            {
                                local.Append(chunk);
                                transcript.Append(chunk);
                            }
                        }

                        if (local.Length > 0)
                            break;

                        Thread.Sleep(waitMs);
                    }

                    return local.ToString();
                }

                bool WaitFor(string token, int maxMs = 8000)
                {
                    var end = DateTime.UtcNow.AddMilliseconds(maxMs);
                    while (DateTime.UtcNow < end)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        if (shell.DataAvailable)
                        {
                            var chunk = shell.Read();
                            if (!string.IsNullOrEmpty(chunk))
                            {
                                transcript.Append(chunk);
                                if (transcript.ToString()
                                              .IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    return true;
                                }
                            }
                        }

                        Thread.Sleep(150);
                    }

                    return false;
                }

                // Kick the CLI so we see an initial prompt.
                WriteLine(string.Empty);
                ReadSome();

                var promptSnapshot = transcript.ToString();

                // Are we already at privileged exec?
                bool hasHash = promptSnapshot.Contains("#");
                bool hasArrow = promptSnapshot.Contains(">");

                // If we see neither '>' nor '#', we'll still try 'enable' –
                // IOS will complain if not appropriate.
                if (!hasHash)
                {
                    WriteLine("enable");
                    ReadSome();

                    if (transcript.ToString().IndexOf("Password", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        // Send enable password
                        WriteLine(enablePassword);
                        if (!WaitFor("#", 8000))
                        {
                            throw new InvalidOperationException(
                                "Did not reach privileged EXEC ('#') after sending enable password. " +
                                "Check SSH/enable credentials. Transcript:\n" + transcript);
                        }
                    }
                    else
                    {
                        // No password prompt; just ensure we have '#'
                        if (!WaitFor("#", 8000))
                        {
                            throw new InvalidOperationException(
                                "Could not detect privileged EXEC prompt ('#') after 'enable'. " +
                                "Transcript:\n" + transcript);
                        }
                    }
                }

                // At this point we should be at a '#' prompt.
                // Small safety: set terminal length to avoid pagination.
                WriteLine("terminal length 0");
                ReadSome();

                // Issue reload
                WriteLine("reload");
                ReadSome();

                // Some IOS versions first ask to save config:
                // "System configuration has been modified. Save? [yes/no]:"
                if (transcript.ToString()
                              .IndexOf("Save? [yes/no]:", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    // For this tool we don't auto-save running-config; answer "no".
                    WriteLine("no");
                    ReadSome();
                }

                // Most versions ask: "Proceed with reload? [confirm]"
                if (transcript.ToString()
                              .IndexOf("[confirm]", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    // Just press Enter for [confirm]
                    WriteLine(string.Empty);
                }
                else
                {
                    // If we never saw [confirm], try to wait briefly in case it appears a bit later
                    if (WaitFor("[confirm]", 5000))
                    {
                        WriteLine(string.Empty);
                    }
                    else
                    {
                        throw new InvalidOperationException(
                            "Did not see expected reload confirmation prompt ('[confirm]'). " +
                            "Reload may not have been issued. Transcript:\n" + transcript);
                    }
                }

                // After confirmation, IOS usually prints something like:
                // "Reload requested by ...", "Reloading...", then disconnects.
                // We don't strictly need to wait for that; disconnecting now is fine.
                client.Disconnect();
            }, cancellationToken);
        }
    }
}
