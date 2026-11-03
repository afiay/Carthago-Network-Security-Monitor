// SPDX-License-Identifier: MIT
// R275 selector-safe trusted runtime context hook.
// SOURCE CANDIDATE — UNVERIFIED. Default is null/unconfigured.
using System;
using System.Threading;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Health;
using Carthago.Models;
using Carthago.Services.TrustedAudit;

namespace Carthago.Services
{
    internal interface IOAuthDeviceFlowTrustedRuntimeContextResolver
    {
        bool TryResolve(
            TrafficRecord record,
            Sensitivity sensitivity,
            DateTime timestampUtc,
            RuleEngineHealthSnapshot healthSnapshot,
            out RuleEvaluationContext? context,
            out string reason);
    }

    public static partial class RuleEngine
    {
        private static readonly AsyncLocal<IOAuthDeviceFlowTrustedRuntimeContextResolver?>
            R275TrustedRuntimeResolver = new();

        private static bool TryResolveR275TrustedContext(
            TrafficRecord record,
            Sensitivity sensitivity,
            DateTime timestampUtc,
            RuleEngineHealthSnapshot healthSnapshot,
            out RuleEvaluationContext? context,
            out string reason)
        {
            context = null;
            reason = "R275_TRUSTED_RUNTIME_RESOLVER_UNAVAILABLE";

            var resolver = R275TrustedRuntimeResolver.Value;
            if (resolver == null)
                return false;

            try
            {
                if (!resolver.TryResolve(
                        record,
                        sensitivity,
                        timestampUtc,
                        healthSnapshot,
                        out context,
                        out reason)
                    || context == null)
                {
                    context = null;
                    if (string.IsNullOrWhiteSpace(reason))
                        reason = "R275_TRUSTED_RUNTIME_CONTEXT_UNAVAILABLE";
                    return false;
                }

                if (!ReferenceEquals(context.Record, record)
                    || context.TimestampUtc != timestampUtc
                    || context.TrustedR275Capability == null
                    || context.TrustedR275PromotionAuthorization == null)
                {
                    context = null;
                    reason = "R275_TRUSTED_RUNTIME_CONTEXT_INVALID";
                    return false;
                }

                reason = "R275_TRUSTED_RUNTIME_CONTEXT_READY";
                return true;
            }
            catch
            {
                context = null;
                reason = "R275_TRUSTED_RUNTIME_RESOLVER_FAILED";
                return false;
            }
        }

        /// <summary>
        /// Internal scoped resolver injection used by trusted runtime bootstrap
        /// and focused tests. The default value is null and therefore cannot
        /// affect ordinary packet evaluation.
        /// </summary>
        internal static IDisposable PushR275TrustedRuntimeResolver(
            IOAuthDeviceFlowTrustedRuntimeContextResolver resolver)
        {
            if (resolver == null)
                throw new ArgumentNullException(nameof(resolver));

            var previous = R275TrustedRuntimeResolver.Value;
            R275TrustedRuntimeResolver.Value = resolver;
            return new R275TrustedRuntimeResolverScope(previous);
        }

        private sealed class R275TrustedRuntimeResolverScope : IDisposable
        {
            private readonly IOAuthDeviceFlowTrustedRuntimeContextResolver? _previous;
            private int _disposed;

            internal R275TrustedRuntimeResolverScope(
                IOAuthDeviceFlowTrustedRuntimeContextResolver? previous)
                => _previous = previous;

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _disposed, 1) != 0)
                    return;
                R275TrustedRuntimeResolver.Value = _previous;
            }
        }
    }
}
