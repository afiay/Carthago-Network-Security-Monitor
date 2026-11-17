// SPDX-License-Identifier: MIT
using System;
using Carthago.Services.Diagnostics;
using Xunit;

namespace Carthago.Tests
{
    public sealed class ParserFailureRateWindowTests
    {
        private static readonly DateTime T = new(2026, 11, 17, 10, 0, 0, DateTimeKind.Utc);
        private static ParserFailureRateWindow.Sample S(int minute, long attempts, long failures,
            string parser = "dns", string epoch = "boot-1")
            => new(parser, epoch, T.AddMinutes(minute), attempts, failures);

        [Fact]
        public void DetectsRateIncreaseWithSufficientDenominator()
        {
            Assert.True(ParserFailureRateWindow.TryDetect(
                S(0, 0, 0), S(5, 1000, 10), S(6, 1000, 10), S(11, 1200, 40),
                100, 10, 0.05, 3, out var result));
            Assert.Equal(30, result.Failures);
            Assert.Equal(200, result.Attempts);
        }

        [Fact]
        public void RejectsResetEpochAndNonComparableParser()
        {
            Assert.False(ParserFailureRateWindow.TryDetect(
                S(0, 0, 0), S(5, 1000, 10), S(6, 1000, 10, epoch: "boot-2"),
                S(11, 1200, 40, epoch: "boot-2"), 100, 10, 0.05, 3, out _));
            Assert.False(ParserFailureRateWindow.TryDetect(
                S(0, 0, 0), S(5, 1000, 10), S(6, 1000, 10, parser: "http"),
                S(11, 1200, 40, parser: "http"), 100, 10, 0.05, 3, out _));
        }

        [Fact]
        public void RejectsInsufficientSamplesAndImpossibleCounters()
        {
            Assert.False(ParserFailureRateWindow.TryDetect(
                S(0, 0, 0), S(5, 1000, 10), S(6, 1000, 10), S(11, 1010, 20),
                100, 10, 0.05, 3, out _));
            Assert.False(ParserFailureRateWindow.TryDetect(
                S(0, 0, 0), S(5, 1000, 10), S(6, 1000, 10), S(11, 1100, 150),
                100, 10, 0.05, 3, out _));
        }

        [Fact]
        public void RejectsOrdinaryBaselineRate()
        {
            Assert.False(ParserFailureRateWindow.TryDetect(
                S(0, 0, 0), S(5, 1000, 10), S(6, 1000, 10), S(11, 1200, 12),
                100, 1, 0.05, 3, out _));
        }
    }
}
