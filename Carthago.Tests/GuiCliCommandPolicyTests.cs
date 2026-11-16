// SPDX-License-Identifier: MIT
using Carthago.Services.Cli;
using Xunit;

namespace Carthago.Tests;

public sealed class GuiCliCommandPolicyTests
{
    [Theory]
    [InlineData("rules summary")]
    [InlineData("carthago rules list --live --offset 10 --limit 30 --json")]
    [InlineData("rules show R1000 --live")]
    [InlineData("sensors health")]
    [InlineData("alerts list --live")]
    [InlineData("capture interfaces")]
    public void ReadOnlyCommandsAreAccepted(string command)
    {
        Assert.True(GuiCliCommandPolicy.TryParse(command, out var args, out var local));
        Assert.NotEmpty(args);
        Assert.Equal(GuiCliLocalAction.None, local);
    }

    [Theory]
    [InlineData("service stop")]
    [InlineData("service start")]
    [InlineData("monitor stop")]
    [InlineData("monitor run --interface TEST")]
    [InlineData("rules list C:\\secrets.csa")]
    [InlineData("powershell -Command Get-Process")]
    [InlineData("rules summary && calc.exe")]
    [InlineData("rules list --live --offset -1 --limit 100")]
    [InlineData("rules list --live --offset 0 --limit 0")]
    public void UnsafeOrUnsupportedCommandsAreRejected(string command)
        => Assert.False(GuiCliCommandPolicy.TryParse(command, out _, out _));

    [Fact]
    public void LocalHelpAndClearAreNotPassedToCli()
    {
        Assert.True(GuiCliCommandPolicy.TryParse("help", out var helpArgs, out var help));
        Assert.Empty(helpArgs);
        Assert.Equal(GuiCliLocalAction.Help, help);
        Assert.True(GuiCliCommandPolicy.TryParse("clear", out var clearArgs, out var clear));
        Assert.Empty(clearArgs);
        Assert.Equal(GuiCliLocalAction.Clear, clear);
    }

    [Fact]
    public void OversizedAndControlCharacterCommandsFailClosed()
    {
        Assert.False(GuiCliCommandPolicy.TryParse(new string('a', GuiCliCommandPolicy.MaxInputLength + 1), out _, out _));
        Assert.False(GuiCliCommandPolicy.TryParse("engine status\nservice stop", out _, out _));
    }
}
