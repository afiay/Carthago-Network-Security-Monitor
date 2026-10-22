// SPDX-License-Identifier: MIT
// File: Converters/BoolToOnlineTextConverter.cs

using System;
using System.Globalization;
using System.Windows.Data;

namespace Carthago.Converters
{
    /// <summary>
    /// Maps a boolean IsOnline -> Online/Offline text.
    /// </summary>
    [ValueConversion(typeof(bool), typeof(string))]
    public sealed class BoolToOnlineTextConverter : IValueConverter
    {
        public string OnlineText { get; set; } = "Online";
        public string OfflineText { get; set; } = "Offline";

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool b && b)
                return OnlineText;

            return OfflineText;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => Binding.DoNothing;
    }
}
