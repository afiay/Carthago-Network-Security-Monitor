// SPDX-License-Identifier: MIT
// File: Converters/HealthHistoryToPointsConverter.cs

using System;
using System.Collections;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace Carthago.Converters
{
    /// <summary>
    /// Converts a sequence of health scores (0-100) into a PointCollection for a tiny sparkline.
    /// Accepts IEnumerable of int/double/string.
    /// </summary>
    [ValueConversion(typeof(IEnumerable), typeof(PointCollection))]
    public sealed class HealthHistoryToPointsConverter : IValueConverter
    {
        public double Width { get; set; } = 70;
        public double Height { get; set; } = 16;

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is not IEnumerable enumerable)
                return new PointCollection();

            var values = enumerable.Cast<object>()
                                   .Select(v =>
                                   {
                                       if (v is double d) return d;
                                       if (v is float f) return (double)f;
                                       if (v is int i) return (double)i;

                                       if (double.TryParse(
                                               v?.ToString() ?? string.Empty,
                                               NumberStyles.Any,
                                               CultureInfo.InvariantCulture,
                                               out var parsed))
                                       {
                                           return parsed;
                                       }

                                       return (double?)null;
                                   })
                                   .Where(x => x.HasValue)
                                   .Select(x => x!.Value)
                                   .ToList();

            if (values.Count == 0)
                return new PointCollection();

            double max = values.Max();
            if (max <= 0) max = 1;

            int n = values.Count;
            if (n == 1)
            {
                // Duplicate single point so we get a horizontal line.
                values.Add(values[0]);
                n = 2;
            }

            var points = new PointCollection();
            for (int i = 0; i < n; i++)
            {
                double x = (Width * i) / (n - 1);
                double y = Height - (values[i] / max) * Height;
                points.Add(new Point(x, y));
            }

            return points;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => Binding.DoNothing;
    }
}
