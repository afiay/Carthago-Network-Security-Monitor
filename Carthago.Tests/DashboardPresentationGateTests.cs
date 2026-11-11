using Carthago.Services;

namespace Carthago.Tests;

public sealed class DashboardPresentationGateTests
{
    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, 1)]
    public void PreferenceChangeRebuildsLayoutOnlyWhenDashboardIsVisible(
        bool isDashboardVisible,
        int expectedLayoutRefreshes)
    {
        var layoutRefreshes = 0;

        DashboardPresentationGate.RunIfVisible(
            isDashboardVisible,
            () => layoutRefreshes++);

        Assert.Equal(expectedLayoutRefreshes, layoutRefreshes);
    }
}
