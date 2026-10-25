// SPDX-License-Identifier: MIT
using System;
using System.Net;
using System.Net.Http;

namespace Carthago.Services
{
    /// <summary>Bounded retries for optional IANA port registry updates.</summary>
    public static class PortRefreshRetryPolicy
    {
        public static bool ShouldRetry(Exception error, int failedAttempt)
        {
            if (failedAttempt >= 3 || error is OperationCanceledException)
                return false;

            if (error is HttpRequestException http && http.StatusCode is { } status)
                return status == HttpStatusCode.RequestTimeout
                    || status == HttpStatusCode.TooManyRequests
                    || (int)status >= 500;

            return true;
        }

        public static TimeSpan FailureCooldown(Exception error)
        {
            if (error is HttpRequestException http && http.StatusCode is { } status
                && (int)status >= 400 && (int)status < 500
                && status != HttpStatusCode.RequestTimeout
                && status != HttpStatusCode.TooManyRequests)
                return TimeSpan.FromHours(24);

            return TimeSpan.FromMinutes(15);
        }

        public static TimeSpan RetryDelay(int failedAttempt)
            => TimeSpan.FromSeconds(Math.Min(120, 5 * Math.Pow(2, Math.Max(0, failedAttempt - 1))));
    }
}
