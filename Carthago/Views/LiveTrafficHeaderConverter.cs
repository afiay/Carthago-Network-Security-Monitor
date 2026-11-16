// SPDX-License-Identifier: MIT
using System;
using System.Globalization;
using System.Windows.Data;
using Carthago.Models;

namespace Carthago.Views;

/// <summary>WPF-only adapter for protocol-aware header display on captured records.</summary>
public sealed class LiveTrafficHeaderConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => LiveTrafficHeaderFormatter.Format(value as TrafficRecord, parameter as string);

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException("Live packet header columns are read-only.");
}
