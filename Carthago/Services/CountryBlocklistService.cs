// SPDX-License-Identifier: MIT
// File: Services/CountryBlocklistService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Services
{
    public sealed class CountryBlocklistService
    {
        public event Action? Changed;

        public IReadOnlyCollection<string> GetAll() =>
            PreferencesService.Current.BlockedCountries
                .OrderBy(code => code, StringComparer.OrdinalIgnoreCase)
                .ToArray();

        public bool IsBlockedIso2(string? iso2)
        {
            var normalized = NormalizeIso2(iso2);
            if (normalized is null) return false;
            return PreferencesService.Current.BlockedCountries.Contains(normalized);
        }

        public void Set(IEnumerable<string> iso2List)
        {
            var normalized = NormalizeAll(iso2List);
            PreferencesService.Update(p => p.BlockedCountries = normalized);

            Changed?.Invoke();
        }

        public void Add(string iso2)
        {
            var normalized = NormalizeIso2(iso2);
            if (normalized is null) return;

            bool changed = false;
            PreferencesService.Update(p =>
            {
                p.BlockedCountries ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                changed = p.BlockedCountries.Add(normalized);
            });

            if (changed)
                Changed?.Invoke();
        }

        public void Remove(string iso2)
        {
            var normalized = NormalizeIso2(iso2);
            if (normalized is null) return;

            bool changed = false;
            PreferencesService.Update(p =>
            {
                p.BlockedCountries ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                changed = p.BlockedCountries.Remove(normalized);
            });

            if (changed)
                Changed?.Invoke();
        }

        private static string? NormalizeIso2(string? iso2)
        {
            if (string.IsNullOrWhiteSpace(iso2)) return null;
            return iso2.Trim().ToUpperInvariant();
        }

        private static HashSet<string> NormalizeAll(IEnumerable<string> iso2List)
        {
            var normalized = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var iso2 in iso2List ?? Array.Empty<string>())
            {
                var code = NormalizeIso2(iso2);
                if (code is not null)
                    normalized.Add(code);
            }

            return normalized;
        }
    }
}
