using System;

namespace Carthago.Services;

internal static class DashboardPresentationGate
{
    public static void RunIfVisible(bool isDashboardVisible, Action callback)
    {
        ArgumentNullException.ThrowIfNull(callback);
        if (isDashboardVisible)
            callback();
    }
}
