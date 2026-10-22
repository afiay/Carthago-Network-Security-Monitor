using System;
using System.Globalization;
using System.Windows.Data;

namespace Carthago.Converters
{
    /// <summary>
    /// Converts UTC/ISO timestamps to local time for display.
    /// Returns a DateTime so XAML StringFormat works (e.g., StringFormat="g").
    /// Rules:
    /// - DateTime.Utc  -> ToLocalTime()
    /// - DateTime.Local -> unchanged
    /// - DateTime.Unspecified -> treated as UTC, then ToLocalTime()
    /// - string (ISO-ish) -> parsed as UTC, then ToLocalTime()
    /// </summary>
    public sealed class UtcToLocalConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            // null -> empty for safety
            if (value is null)
                return string.Empty;

            // DateTime value
            if (value is DateTime dt)
            {
                return dt.Kind switch
                {
                    DateTimeKind.Utc => dt.ToLocalTime(),
                    DateTimeKind.Local => dt,
                    _ => DateTime.SpecifyKind(dt, DateTimeKind.Utc).ToLocalTime()
                };
            }

            // NOTE: Nullable<DateTime> boxes as DateTime or null,
            // so the branch above handles DateTime? that has a value.
            // Strings: try parse as UTC, then localize.
            if (value is string s && !string.IsNullOrWhiteSpace(s))
            {
                if (DateTime.TryParse(
                        s,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out var parsedUtc))
                {
                    return parsedUtc.ToLocalTime();
                }
                // If unparseable, return original string instead of breaking bindings
                return s;
            }

            // Fallback: return as-is
            return value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => value; // one-way in this app
    }
}
