// SPDX-License-Identifier: MIT
using System.Windows.Media;

namespace Carthago.Views
{
    public sealed class WorkspaceKpiVm
    {
        public string Title { get; init; } = string.Empty;
        public string Value { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;
        public string Glyph { get; init; } = string.Empty;
        public Brush AccentBrush { get; init; } = Brushes.SlateGray;
    }
}
