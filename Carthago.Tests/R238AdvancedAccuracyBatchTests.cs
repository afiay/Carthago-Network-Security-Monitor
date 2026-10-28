// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R238AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch236240Context.Sample(238);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch236240Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R238_SmartHomeHubCloudBurstRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Sixty_Independent_Attributed_Vendor_Requests_Reach_Burst()
    { var rule = new R238_SmartHomeHubCloudBurstRule(); var source = Sample().Source;
      for (int i = 0; i < 59; i++) { var r = Sample(); r.Source = source;
        Assert.False((await rule.EvaluateAsync(At(r, i))).Matched); }
      var last = Sample(); last.Source = source;
      Assert.True((await rule.EvaluateAsync(At(last, 59))).Matched); }
    [Fact] public async Task Single_Hub_Heartbeat_Is_Benign()
        => Assert.False(await Hit(Sample()));
    [Fact] public async Task Info_Spoof_Without_Typed_Vendor_Host_Is_Rejected()
    { var r = Sample(); r.Sni = "unknown.example"; r.Info = "smartthings cloud sync"; Assert.False(await Hit(r)); }
    [Fact] public async Task Vendor_Host_Without_Hub_Process_Is_Rejected()
    { var r = Sample(); r.ProcessName = null; Assert.False(await Hit(r)); }
    [Fact] public async Task Lookalike_Vendor_Host_Is_Rejected()
    { var r = Sample(); r.Sni = "api.smartthings.com.evil.example"; Assert.False(await Hit(r)); }
    [Fact] public async Task Internal_Destination_Is_Not_Cloud_Egress()
    { var r = Sample(); r.Destination = "10.236.1.20"; Assert.False(await Hit(r)); }
    [Fact] public async Task External_Source_Is_Not_An_Attributed_Local_Hub()
    { var r = Sample(); r.Source = "198.51.100.25"; Assert.False(await Hit(r)); }
    [Fact] public async Task Tls_Protocol_Contradiction_Is_Rejected()
    { var r = Sample(); r.ApplicationProtocol = "HTTP"; Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Id_Does_Not_Inflate_Burst()
    { var rule = new R238_SmartHomeHubCloudBurstRule(); var r = Sample();
      for (int i = 0; i < 70; i++) Assert.False((await rule.EvaluateAsync(At(r, i))).Matched); }
    [Fact] public async Task Independent_Hubs_Do_Not_Combine_Bursts()
    { var rule = new R238_SmartHomeHubCloudBurstRule(); var a = Sample().Source; var b = Sample().Source;
      for (int i = 0; i < 30; i++) { var r = Sample(); r.Source = a;
        Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        r = Sample(); r.Source = b; Assert.False((await rule.EvaluateAsync(At(r, i))).Matched); } }
    [Fact] public async Task Out_Of_Order_Does_Not_Advance_Window()
    { var rule = new R238_SmartHomeHubCloudBurstRule(); var r = Sample();
      Assert.False((await rule.EvaluateAsync(At(r, 100))).Matched);
      var old = Sample(); old.Source = r.Source;
      Assert.False((await rule.EvaluateAsync(At(old, 1))).Matched); }
    [Fact] public void Original_Shadow_Mode_And_Floor()
    { var p = new R238_SmartHomeHubCloudBurstRule().PrecisionProfile;
      Assert.Equal(72, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode); }
}
