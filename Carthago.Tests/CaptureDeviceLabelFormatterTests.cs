using System;
using System.Collections.Generic;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class CaptureDeviceLabelFormatterTests
{
    private const string WifiGuid = "1AA3C21B-2840-45CC-B855-62EA63BF9282";
    private const string EthernetGuid = "34E6B0CB-0FF4-4EE8-9F5A-3D51E5982F72";

    [Fact]
    public void NpcapGuidMapsToWindowsFriendlyWifiNameAndHardware()
    {
        var adapters = new[]
        {
            new CaptureAdapterIdentity(EthernetGuid, "Ethernet", "Realtek PCIe GbE Family Controller"),
            new CaptureAdapterIdentity(WifiGuid.ToLowerInvariant(), "Wi-Fi", "Intel(R) Wi-Fi 6 AX201")
        };

        var label = CaptureDeviceLabelFormatter.FormatNpcapLabel(
            @"\\Device\\NPF_{1AA3C21B-2840-45CC-B855-62EA63BF9282}",
            "Microsoft",
            adapters);

        Assert.Equal("Npcap: Wi-Fi — Intel(R) Wi-Fi 6 AX201", label);
        Assert.DoesNotContain("NPF_", label);
    }

    [Fact]
    public void WindowsRenamedEthernetAliasTakesPrecedenceOverVendorDescription()
    {
        var adapters = new[]
        {
            new CaptureAdapterIdentity("{" + EthernetGuid + "}", "Office Ethernet", "Realtek USB GbE Adapter")
        };

        var label = CaptureDeviceLabelFormatter.FormatNpcapLabel(
            @"\\Device\\NPF_{" + EthernetGuid + "}",
            "Microsoft",
            adapters);

        Assert.Equal("Npcap: Office Ethernet — Realtek USB GbE Adapter", label);
    }

    [Fact]
    public void IdenticalAdapterNameAndDescriptionAreNotRepeated()
    {
        var adapters = new[] { new CaptureAdapterIdentity(WifiGuid, "VMware Network Adapter VMnet8", "VMware Network Adapter VMnet8") };
        Assert.Equal("Npcap: VMware Network Adapter VMnet8",
            CaptureDeviceLabelFormatter.FormatNpcapLabel(WifiGuid, "VMware Virtual Ethernet Adapter", adapters));
    }

    [Fact]
    public void LoopbackUsesReadableLabelWhenWindowsHasNoMatch()
    {
        Assert.Equal("Npcap: Loopback (this computer)",
            CaptureDeviceLabelFormatter.FormatNpcapLabel(
                @"\\Device\\NPF_{00C267BA-1280-4708-A502-FECF52622CCF}",
                "MS NDIS 6.0 LoopBack Driver", Array.Empty<CaptureAdapterIdentity>()));
    }

    [Fact]
    public void UnmatchedGenericDescriptionsRemainDistinguishableWithoutFullNpcapPaths()
    {
        var first = CaptureDeviceLabelFormatter.FormatNpcapLabel(
            @"\\Device\\NPF_{" + WifiGuid + "}", "Microsoft", Array.Empty<CaptureAdapterIdentity>());
        var second = CaptureDeviceLabelFormatter.FormatNpcapLabel(
            @"\\Device\\NPF_{" + EthernetGuid + "}", "Microsoft", Array.Empty<CaptureAdapterIdentity>());

        Assert.StartsWith("Npcap: Microsoft [", first);
        Assert.NotEqual(first, second);
        Assert.DoesNotContain("NPF_", first);
    }

    [Fact]
    public void DescriptiveVendorFallbackDoesNotInventWindowsAlias()
    {
        var label = CaptureDeviceLabelFormatter.FormatNpcapLabel(
            @"\\Device\\NPF_{12C48446-ED58-43F3-BB45-2687937FAD33}",
            "VMware Virtual Ethernet Adapter",
            Array.Empty<CaptureAdapterIdentity>());

        Assert.Equal("Npcap: VMware Virtual Ethernet Adapter", label);
    }

    [Fact]
    public void MissingOrInvalidDeviceIdCannotBorrowAnotherAdapterAlias()
    {
        var adapters = new[] { new CaptureAdapterIdentity(WifiGuid, "Wi-Fi", "Intel") };
        Assert.Equal("Npcap: Unknown adapter",
            CaptureDeviceLabelFormatter.FormatNpcapLabel(@"\\Device\\NPF_invalid", null, adapters));
    }

    [Fact]
    public void NullWindowsAdapterCollectionIsRejected()
    {
        Assert.Throws<ArgumentNullException>(() =>
            CaptureDeviceLabelFormatter.FormatNpcapLabel("invalid", "Microsoft", null!));
    }
}
