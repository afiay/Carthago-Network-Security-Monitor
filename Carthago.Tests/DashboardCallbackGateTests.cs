using Carthago.Services;

namespace Carthago.Tests;

public sealed class DashboardCallbackGateTests
{
    [Fact]
    public void QueuedDashboardUpdate_DoesNotRunAfterClose()
    {
        var gate = new DashboardCallbackGate();
        var updates = 0;
        Action queuedUpdate = () => gate.RunIfOpen(() => updates++);

        queuedUpdate();
        gate.Close();
        queuedUpdate();
        gate.Close();
        queuedUpdate();

        Assert.Equal(1, updates);
        Assert.False(gate.IsOpen);
    }
}
