// SPDX-License-Identifier: MIT
using System;
using System.Reflection;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

[CollectionDefinition("Global evidence window safety", DisableParallelization = true)]
public sealed class GlobalEvidenceWindowCollection { }

[Collection("Global evidence window safety")]
public sealed class CatalogWideSharedWindowSafetyTests
{
    // Exercise the actual internal shared burst counter through reflection
    // rather than adding publicly callable production testing backdoors.
    private static readonly MethodInfo Observe =
        typeof(EvidenceDrivenPrecisionRuleBase).GetMethod(
            "ObserveCount", BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("Shared window observer not found.");

    private static int Count(string key, DateTime time, TimeSpan window)
        => (int)(Observe.Invoke(null, new object[] { key, time, window })
            ?? throw new InvalidOperationException("Window observer returned no count."));

    [Fact]
    public void Shared_Window_Only_Counts_Current_In_Order_Observations()
    {
        var key = "replay-window-" + Guid.NewGuid().ToString("N");
        var time = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);
        var window = TimeSpan.FromMinutes(5);
        try
        {
            EvidenceDrivenPrecisionRuleBase.ResetSharedStateForReplay();

            Assert.Equal(1, Count(key, time, window));
            Assert.Equal(2, Count(key, time.AddSeconds(30), window));
            // A later clock jump must not contaminate an earlier replay.
            Assert.Equal(1, Count(key, time.AddMinutes(15), window));
            Assert.Equal(1, Count(key, time.AddMinutes(1), window));
            Assert.Equal(1, Count(key, time.AddMinutes(9), window));

            EvidenceDrivenPrecisionRuleBase.ResetSharedStateForReplay();
            Assert.Equal(1, Count(key, time, window));
        }
        finally
        {
            EvidenceDrivenPrecisionRuleBase.ResetSharedStateForReplay();
        }
    }

    [Fact]
    public void Shared_Window_Retains_No_More_Than_Bounded_Observations_Per_Key()
    {
        var key = "bounded-window-" + Guid.NewGuid().ToString("N");
        var time = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);
        try
        {
            EvidenceDrivenPrecisionRuleBase.ResetSharedStateForReplay();

            var count = 0;
            for (var index = 0; index < 700; index++)
            {
                count = Count(key, time.AddSeconds(index), TimeSpan.FromHours(2));
                Assert.InRange(count, 1, 512);
            }
            Assert.Equal(512, count);
            Assert.Equal(0, Count(key, time, TimeSpan.Zero));
        }
        finally
        {
            EvidenceDrivenPrecisionRuleBase.ResetSharedStateForReplay();
        }
    }
}
