using System;
using System.Collections.Generic;

namespace Carthago.Services
{
    /// <summary>Windows interface identity used to label an existing Npcap capture device.</summary>
    public sealed record CaptureAdapterIdentity(string Id, string Name, string Description);

    /// <summary>
    /// Maps an Npcap NPF_{GUID} capture identifier to the corresponding Windows
    /// network connection name. This only formats UI labels: capture uses its
    /// original SharpPcap device instance, not the formatted string.
    /// </summary>
    public static class CaptureDeviceLabelFormatter
    {
        public static string FormatNpcapLabel(
            string? captureDeviceName,
            string? captureDescription,
            IEnumerable<CaptureAdapterIdentity> windowsAdapters)
        {
            if (windowsAdapters is null)
                throw new ArgumentNullException(nameof(windowsAdapters));

            var deviceGuid = ParseDeviceGuid(captureDeviceName);
            if (deviceGuid.HasValue)
            {
                foreach (var adapter in windowsAdapters)
                {
                    if (adapter is null ||
                        !Guid.TryParse(adapter.Id, out var adapterGuid) ||
                        adapterGuid != deviceGuid.Value ||
                        string.IsNullOrWhiteSpace(adapter.Name))
                        continue;

                    var alias = adapter.Name.Trim();
                    var model = adapter.Description?.Trim();
                    return string.IsNullOrWhiteSpace(model) ||
                           string.Equals(alias, model, StringComparison.OrdinalIgnoreCase)
                        ? $"Npcap: {alias}"
                        : $"Npcap: {alias} — {model}";
                }
            }

            var description = captureDescription?.Trim();
            var looksLikeLoopback =
                (description?.Contains("Loopback", StringComparison.OrdinalIgnoreCase) ?? false) ||
                (captureDeviceName?.Contains("NPF_Loopback", StringComparison.OrdinalIgnoreCase) ?? false);
            if (looksLikeLoopback)
                return "Npcap: Loopback (this computer)";

            // Unmatched generic driver names aren't unique; include only a short
            // ID to distinguish them. The full NPF path remains in the tooltip.
            if (string.IsNullOrWhiteSpace(description) ||
                string.Equals(description, "Microsoft", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(description, "NdisWan Adapter", StringComparison.OrdinalIgnoreCase))
            {
                var display = string.IsNullOrWhiteSpace(description) ? "Unknown adapter" : description;
                return deviceGuid.HasValue
                    ? $"Npcap: {display} [{deviceGuid.Value.ToString("N")[..8]}]"
                    : $"Npcap: {display}";
            }

            return $"Npcap: {description}";
        }

        public static Guid? ParseDeviceGuid(string? deviceName)
        {
            if (string.IsNullOrWhiteSpace(deviceName))
                return null;

            // Most Windows Npcap names look like \\Device\\NPF_{GUID}.
            var open = deviceName.LastIndexOf('{');
            if (open >= 0)
            {
                var close = deviceName.IndexOf('}', open + 1);
                if (close > open && Guid.TryParse(deviceName.Substring(open, close - open + 1), out var guid))
                    return guid;
            }

            // Also accept GUID-only names and NPF_ identifiers without braces.
            if (Guid.TryParse(deviceName, out var bareGuid))
                return bareGuid;

            var prefix = deviceName.LastIndexOf("NPF_", StringComparison.OrdinalIgnoreCase);
            if (prefix >= 0 && Guid.TryParse(deviceName[(prefix + 4)..], out var npfGuid))
                return npfGuid;

            return null;
        }
    }
}
