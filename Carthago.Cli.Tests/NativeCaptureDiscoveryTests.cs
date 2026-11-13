// SPDX-License-Identifier: MIT
using System.Text.Json;
using Carthago.Cli;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class NativeCaptureDiscoveryTests
{
    private sealed class Api:NativeCaptureDiscovery.IApi
    {
        internal bool Fail,Disposed;
        internal NativeCaptureDiscovery.Interface[] Rows=Array.Empty<NativeCaptureDiscovery.Interface>();
        public string? Version()=>"libpcap test";
        public IReadOnlyList<NativeCaptureDiscovery.Interface> Enumerate()
        {
            if(Fail)throw new InvalidOperationException("private-native-detail");
            return Rows;
        }
        public void Dispose()=>Disposed=true;
    }

    [Fact]
    public void UnsupportedPlatformNeverLoadsLibrary()
    {
        var r=NativeCaptureDiscovery.Discover("unsupported",_=>throw new Exception());
        Assert.Equal("unsupported_platform",r.Reason);
        Assert.Equal("not_attempted",r.EnumerationStatus);
    }

    [Fact]
    public void MissingLibraryIsExplicit()
    {
        var r=NativeCaptureDiscovery.Discover("libpcap",_=>null);
        Assert.Equal("unavailable",r.LibraryStatus);
        Assert.Empty(r.Interfaces);
    }

    [Fact]
    public void LoaderExceptionIsSanitized()
    {
        var r=NativeCaptureDiscovery.Discover("wpcap",_=>throw new Exception("private"));
        Assert.Equal("library_load_failed",r.Reason);
    }

    [Fact]
    public void EnumeratesExactSortedIdsAndDisposes()
    {
        var api=new Api{Rows=new[]{new NativeCaptureDiscovery.Interface("lo",true),
            new NativeCaptureDiscovery.Interface("eth0",false)}};
        var r=NativeCaptureDiscovery.Discover("libpcap",_=>api);
        Assert.Equal("available",r.LibraryStatus);Assert.Equal("succeeded",r.EnumerationStatus);
        Assert.Equal(new[]{"eth0","lo"},r.Interfaces.Select(i=>i.Id).ToArray());
        Assert.True(r.Interfaces[1].Loopback);Assert.True(api.Disposed);
    }

    [Fact]
    public void EmptyListIsSuccessfulDiscoveryNotCaptureReadiness()
    {
        var api=new Api();var r=NativeCaptureDiscovery.Discover("wpcap",_=>api);
        Assert.Equal("succeeded",r.EnumerationStatus);Assert.Empty(r.Interfaces);Assert.True(api.Disposed);
    }

    [Fact]
    public void EnumerationFailureDisposesAndSuppressesPrivateDetail()
    {
        var api=new Api{Fail=true};var r=NativeCaptureDiscovery.Discover("libpcap",_=>api);
        Assert.Equal("available",r.LibraryStatus);Assert.Equal("failed",r.EnumerationStatus);
        Assert.Equal("interface_enumeration_failed",r.Reason);Assert.True(api.Disposed);
    }

    [Theory]
    [InlineData("bad\nname")]
    [InlineData("")]
    [InlineData("duplicate")]
    public void InvalidOrDuplicateNamesFailWithoutPartialList(string name)
    {
        var api=new Api{Rows=new[]{new NativeCaptureDiscovery.Interface(name,false),
            new NativeCaptureDiscovery.Interface(name,true)}};
        var r=NativeCaptureDiscovery.Discover("libpcap",_=>api);
        Assert.Equal("failed",r.EnumerationStatus);Assert.Empty(r.Interfaces);Assert.True(api.Disposed);
    }

    [Fact]
    public void ExcessiveListFailsClosed()
    {
        var api=new Api{Rows=Enumerable.Range(0,257).Select(i=>new NativeCaptureDiscovery.Interface("if"+i,false)).ToArray()};
        var r=NativeCaptureDiscovery.Discover("libpcap",_=>api);
        Assert.Equal("failed",r.EnumerationStatus);Assert.True(api.Disposed);
    }

    [Fact]
    public async Task InvalidCliArgumentsFailBeforeDiscovery()
    {
        using var output=new StringWriter();using var error=new StringWriter();
        Assert.Equal(2,await CliApplication.RunAsync(new[]{"capture","interfaces","extra","--json"},output,error));
        Assert.Empty(output.ToString());
    }

    [Fact]
    public async Task CancelledCliDoesNotDiscover()
    {
        using var output=new StringWriter();using var error=new StringWriter();
        using var cancel=new CancellationTokenSource();cancel.Cancel();
        Assert.Equal(130,await CliApplication.RunAsync(new[]{"capture","doctor","--json"},output,error,cancel.Token));
        Assert.Empty(output.ToString());
    }
}
