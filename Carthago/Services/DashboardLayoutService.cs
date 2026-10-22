// SPDX-License-Identifier: MIT
// File: Services/DashboardLayoutService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Services
{
    public static class DashboardLayoutService
    {
        public static void NormalizeOrder(IList<DashboardWidgetConfig> widgets)
        {
            if (widgets == null)
                return;

            var ordered = widgets
                .Where(widget => widget != null)
                .OrderBy(widget => widget.Order)
                .ThenBy(widget => widget.Row)
                .ThenBy(widget => widget.Column)
                .ToList();

            for (var index = 0; index < ordered.Count; index++)
                ordered[index].Order = index;

            widgets.Clear();
            foreach (var widget in ordered)
                widgets.Add(widget);
        }

        public static bool RemoveWidget(DashboardPreferences preferences, string? widgetId)
        {
            if (preferences?.Widgets == null || string.IsNullOrWhiteSpace(widgetId))
                return false;

            var removed = preferences.Widgets.RemoveAll(widget =>
                string.Equals(widget.Id, widgetId, StringComparison.OrdinalIgnoreCase)) > 0;

            if (removed)
                NormalizeOrder(preferences.Widgets);

            return removed;
        }

        public static bool MoveWidget(DashboardPreferences preferences, string? widgetId, int delta)
        {
            if (preferences?.Widgets == null || string.IsNullOrWhiteSpace(widgetId) || delta == 0)
                return false;

            var ordered = preferences.Widgets
                .OrderBy(widget => widget.Order)
                .ThenBy(widget => widget.Row)
                .ThenBy(widget => widget.Column)
                .ToList();

            var index = ordered.FindIndex(widget => string.Equals(widget.Id, widgetId, StringComparison.OrdinalIgnoreCase));
            if (index < 0)
                return false;

            var next = Math.Clamp(index + delta, 0, ordered.Count - 1);
            if (next == index)
                return false;

            var item = ordered[index];
            ordered.RemoveAt(index);
            ordered.Insert(next, item);
            for (var i = 0; i < ordered.Count; i++)
                ordered[i].Order = i;
            preferences.Widgets = ordered;
            return true;
        }

        public static bool MoveWidgetBefore(DashboardPreferences preferences, string? sourceWidgetId, string? targetWidgetId)
        {
            if (preferences?.Widgets == null ||
                string.IsNullOrWhiteSpace(sourceWidgetId) ||
                string.IsNullOrWhiteSpace(targetWidgetId) ||
                string.Equals(sourceWidgetId, targetWidgetId, StringComparison.OrdinalIgnoreCase))
                return false;

            var ordered = preferences.Widgets
                .OrderBy(widget => widget.Order)
                .ThenBy(widget => widget.Row)
                .ThenBy(widget => widget.Column)
                .ToList();

            var source = ordered.FindIndex(widget => string.Equals(widget.Id, sourceWidgetId, StringComparison.OrdinalIgnoreCase));
            var target = ordered.FindIndex(widget => string.Equals(widget.Id, targetWidgetId, StringComparison.OrdinalIgnoreCase));
            if (source < 0 || target < 0)
                return false;

            var item = ordered[source];
            ordered.RemoveAt(source);
            if (target > source)
                target--;
            ordered.Insert(target, item);

            for (var i = 0; i < ordered.Count; i++)
                ordered[i].Order = i;
            preferences.Widgets = ordered;
            return true;
        }
    }
}
