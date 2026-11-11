// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Windows xUnit execution deferred by owner.
using Carthago.Views;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkInvestigationMatchNavigationTests
{
    [Theory]
    [InlineData(3, -1, 1, 0)]
    [InlineData(3, -1, -1, 2)]
    [InlineData(3, 0, 1, 1)]
    [InlineData(3, 2, -1, 1)]
    [InlineData(3, 2, 1, -1)]
    [InlineData(3, 0, -1, -1)]
    [InlineData(0, -1, 1, -1)]
    [InlineData(3, 9, 1, -1)]
    [InlineData(3, 1, 0, -1)]
    public void Next_Match_Position_Does_Not_Wrap_Or_Use_Stale_Row_Indices(
        int count, int current, int direction, int expected)
        => Assert.Equal(expected, NetworkInvestigationPage.NextMatchIndex(count, current, direction));
}
