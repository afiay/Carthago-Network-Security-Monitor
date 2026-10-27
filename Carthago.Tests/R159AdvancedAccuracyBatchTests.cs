// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R159AdvancedAccuracyBatchTests
{

    [Fact] public async Task Sensitive_Env_Endpoint_Matches()
    {
        Assert.True((await new R159_SpringActuatorExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/actuator/env")))).Matched);
    }
    [Fact] public async Task Heapdump_Subpath_Matches()
    {
        Assert.True((await new R159_SpringActuatorExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/actuator/heapdump/1")))).Matched);
    }
    [Fact] public async Task Health_Check_Is_Benign()
    {
        Assert.False((await new R159_SpringActuatorExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/actuator/health")))).Matched);
    }
    [Fact] public async Task Lookalike_Environment_Path_Is_Not_Env()
    {
        Assert.False((await new R159_SpringActuatorExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/actuator/environment")))).Matched);
    }
    [Fact] public async Task Forged_Packet_Info_Is_Not_Endpoint()
    {
        var r=NetworkBatch156165Context.Http("/health");r.Info="GET /actuator/env";
        Assert.False((await new R159_SpringActuatorExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Internal_Monitoring_Stays_Out_Of_Scope()
    {
        var r=NetworkBatch156165Context.Http("/actuator/env");r.Source="10.156.0.11";
        Assert.False((await new R159_SpringActuatorExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Observation_Does_Not_Realert()
    {
        var rule=new R159_SpringActuatorExposureProbeRule();
        Assert.True((await rule.EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/actuator/env"),20))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/actuator/env"),10))).Matched);
    }
    [Fact] public void Configured_Mode_And_Confidence_Floor_Remain_Unchanged()
    {
        var profile=new R159_SpringActuatorExposureProbeRule().PrecisionProfile;
        Assert.Equal(78,profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert,profile.DefaultMode);
    }
}
