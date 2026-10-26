// SPDX-License-Identifier: MIT
// File: Engine/RuleEngine.Replay.cs
using System;
using System.Threading;
using Carthago.Engine.Rules.CloudSaas;
using Carthago.Engine.Rules.Dns;
using Carthago.Engine.Rules.Expansion;
using Carthago.Engine.Rules.IotOt;
using Carthago.Services.Baseline;
using Carthago.Services.Diagnostics;

namespace Carthago.Services
{
    public static partial class RuleEngine
    {
        internal static void ResetRuntimeStateForReplay()
        {
            _lastAlertAt.Clear();
            _lastSeenSrc.Clear();
            _entityHits.Clear();
            _lastTrace = null;

            Interlocked.Exchange(ref _evalCalls, 0);
            Interlocked.Exchange(ref _emittedEvents, 0);
            _lastDiagPrint = DateTime.MinValue;
            _lastDetectionAt = DateTime.MinValue;
            _lastCleanup = DateTime.UtcNow;

            _sourceToPorts.Clear();
            _srcDstToPorts.Clear();
            _packetTimes.Clear();
            _floodWindows.Clear();
            _authAttempts.Clear();
            _dnsQueries.Clear();
            _beaconing.Clear();
            _exfilBytes.Clear();
            _arpTable.Clear();
            _dhcpActivity.Clear();
            _hostSweeps.Clear();
            _icmpTimes.Clear();
            _icmpWindow.Clear();
            _icmpBytes.Clear();
            _nxdomain.Clear();
            _ja4Counts.Clear();
            _sshFpCounts.Clear();
            _adminSweeps.Clear();
            _dnsTxtBySrc.Clear();
            _pairBytes.Clear();
            _sniJa4Drift.Clear();
            _quicHiEntropyBySrc.Clear();
            _dohBySrc.Clear();
            _asnSeenAnywhere.Clear();
            _asnSeenOnSensitive.Clear();
            _encFlow.Clear();
            _ja4SniFanout.Clear();
            _quicAlpnCounts.Clear();
            _tlsSniByFlow.Clear();
            _altDohSeenBySrc.Clear();

            DnsPrecisionDetectionRuleBase.ResetSharedStateForReplay();
            CloudSaasPrecisionDetectionRuleBase.ResetSharedStateForReplay();
            IotOtPrecisionDetectionRuleBase.ResetSharedStateForReplay();
            IdentityAccessPrecisionDetectionRuleBase.ResetSharedStateForReplay();
            HttpApiPrecisionDetectionRuleBase.ResetSharedStateForReplay();
            CloudDevPrecisionDetectionRuleBase.ResetSharedStateForReplay();
            EvidenceDrivenPrecisionRuleBase.ResetSharedStateForReplay();
            PlatformHealthAdvancedPrecisionDetectionRuleBase.ResetSharedStateForReplay();
            TlsPkiPrecisionDetectionRuleBase.ResetSharedStateForReplay();
            EvasionInfraPrecisionDetectionRuleBase.ResetSharedStateForReplay();
            BaselineStore.Current.ClearAsync().GetAwaiter().GetResult();

            RuleEngineMetrics.Reset();
            RuleEngineHealthState.Reset();
            RuleRuntimeTelemetryStore.Reset();
            _noiseBudgetEvaluator.Reset();
        }
    }
}
