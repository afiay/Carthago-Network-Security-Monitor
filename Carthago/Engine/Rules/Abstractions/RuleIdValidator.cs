// SPDX-License-Identifier: MIT
// Canonical numeric core IDs and separate content-pack IDs.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;

namespace Carthago.Engine.Rules
{
    public static class RuleIdValidator
    {
        private static readonly Regex CoreRuleId = new(@"^R(?:00[1-9]|0[1-9][0-9]|[1-9][0-9]{2,})$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex PackRuleId = new(@"^(?!R[0-9]+$)[A-Z][A-Z0-9]{1,9}[0-9]{3}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

        public static bool IsValid(string? ruleId) => IsCoreRuleId(ruleId) || IsPackRuleId(ruleId);
        public static bool IsCoreRuleId(string? ruleId) => TryGetCoreNumber(ruleId, out _);

        // At least three digits, minimum-width padding, positive Int32, no aliases.
        // Existing callers may trim surrounding whitespace; boundary readers can
        // require exact canonical text before calling this method.
        public static bool TryGetCoreNumber(string? ruleId, out int number)
        {
            number = 0;
            if (string.IsNullOrWhiteSpace(ruleId)) return false;
            string value = ruleId.Trim();
            return CoreRuleId.IsMatch(value) && int.TryParse(value.AsSpan(1),
                NumberStyles.None, CultureInfo.InvariantCulture, out number) && number > 0;
        }

        public static bool IsPackRuleId(string? ruleId)
            => !string.IsNullOrWhiteSpace(ruleId) && PackRuleId.IsMatch(ruleId.Trim());

        public static string Normalize(string ruleId)
            => (ruleId ?? string.Empty).Trim().ToUpperInvariant();

        // Core IDs form the R group and sort by numeric value; all other IDs
        // keep their historical ordinal-ignore-case ordering. Never truncate
        // an ID or compare its suffix alone against a pack identifier.
        public static IComparer<string> NumericComparer { get; } =
            Comparer<string>.Create(CompareIds);

        private static int CompareIds(string? left, string? right)
        {
            if (left == null || right == null)
                return StringComparer.OrdinalIgnoreCase.Compare(left, right);
            bool leftCore = TryGetCoreNumber(Normalize(left), out int a);
            bool rightCore = TryGetCoreNumber(Normalize(right), out int b);
            if (leftCore && rightCore) return a.CompareTo(b);
            return StringComparer.OrdinalIgnoreCase.Compare(leftCore ? "R" : left, rightCore ? "R" : right);
        }

        // Keep the original internal helpers for existing consumers.
        internal static int CoreOrder(string ruleId) => TryGetCoreNumber(ruleId, out var n) ? n : int.MaxValue;
        internal static string SortGroup(string ruleId) => IsCoreRuleId(ruleId) ? "R" : ruleId;
    }
}
