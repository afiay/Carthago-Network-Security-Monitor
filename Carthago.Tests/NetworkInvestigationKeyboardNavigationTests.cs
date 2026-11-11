// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Windows test execution owner-deferred.
using System.Windows.Input;
using Carthago.Views;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkInvestigationKeyboardNavigationTests
{
    [Theory]
    [InlineData(Key.Up, ModifierKeys.Alt, -1)]
    [InlineData(Key.Down, ModifierKeys.Alt, 1)]
    [InlineData(Key.Up, ModifierKeys.None, 0)]
    [InlineData(Key.Down, ModifierKeys.Control, 0)]
    [InlineData(Key.Down, ModifierKeys.Alt | ModifierKeys.Shift, 0)]
    [InlineData(Key.Left, ModifierKeys.Alt, 0)]
    public void Only_Exact_Alt_Up_Down_Invokes_Result_Navigation(Key key, ModifierKeys modifiers, int expected)
        => Assert.Equal(expected, NetworkInvestigationPage.MatchKeyboardDirection(key, modifiers));
}
