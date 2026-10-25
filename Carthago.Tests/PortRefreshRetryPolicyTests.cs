using System.Net;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class PortRefreshRetryPolicyTests
{
    [Theory]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.NotFound)]
    public void Permanent_Http_Failures_Are_Not_Retried(HttpStatusCode status)
    {
        Assert.False(PortRefreshRetryPolicy.ShouldRetry(new HttpRequestException("rejected", null, status), 1));
    }

    [Fact]
    public void Temporary_Failure_Has_Bounded_Retries()
    {
        var failure = new HttpRequestException("temporary", null, HttpStatusCode.ServiceUnavailable);
        Assert.True(PortRefreshRetryPolicy.ShouldRetry(failure, 1));
        Assert.True(PortRefreshRetryPolicy.ShouldRetry(failure, 2));
        Assert.False(PortRefreshRetryPolicy.ShouldRetry(failure, 3));
    }

    [Fact]
    public void Retry_Cooldown_Distinguishes_Access_Denied_From_Transient_Failure()
    {
        Assert.Equal(TimeSpan.FromHours(24), PortRefreshRetryPolicy.FailureCooldown(new HttpRequestException("403", null, HttpStatusCode.Forbidden)));
        Assert.Equal(TimeSpan.FromMinutes(15), PortRefreshRetryPolicy.FailureCooldown(new HttpRequestException("503", null, HttpStatusCode.ServiceUnavailable)));
    }
}
