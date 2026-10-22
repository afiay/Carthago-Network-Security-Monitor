// SPDX-License-Identifier: MIT
// File: Models/AppPreferences.Blocking.cs
using System;
using System.Collections.Generic;

namespace Carthago.Models
{
    public partial class AppPreferences
    {
        /// <summary>
        /// ISO-3166-1 alpha-2 country codes to block (e.g., "RU", "CN").
        /// Stored case-insensitively; services/UI should normalize to ToUpperInvariant().
        /// </summary>
        public HashSet<string> BlockedCountries { get; set; } =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Master switch for country blocking logic (checked by capture/pipeline).
        /// </summary>
        public bool EnableCountryBlocking { get; set; } = false;

        /// <summary>
        /// Whether blocking applies to Source, Destination, or both.
        /// </summary>
        public CountryBlockApplyTo CountryBlockApplyTo { get; set; } = CountryBlockApplyTo.Both;
    }

    public enum CountryBlockApplyTo
    {
        Source,
        Destination,
        Both
    }
}
