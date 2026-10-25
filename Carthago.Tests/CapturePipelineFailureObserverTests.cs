using System;
using System.Threading.Tasks;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class CapturePipelineFailureObserverTests
{
    [Theory]
    [InlineData(false, "reader")]
    [InlineData(true, "source")]
    public async Task ReportsEitherTaskFailureWithoutWaitingForTheOther(bool failSource, string expectedStage)
    {
        var source = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var reader = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var reported = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        CapturePipelineFailureObserver.Observe(source.Task, reader.Task,
            (stage, _) => reported.TrySetResult(stage));

        (failSource ? source : reader).SetException(new InvalidOperationException("Pipeline stopped"));
        Assert.Equal(expectedStage, await reported.Task.WaitAsync(TimeSpan.FromSeconds(5)));

        (failSource ? reader : source).SetResult(true);
    }
}
