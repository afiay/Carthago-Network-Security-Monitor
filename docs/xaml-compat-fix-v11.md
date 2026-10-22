# Carthago v11 — WPF XAML Compatibility Fix

This pass fixes a WPF compile error introduced during the v10 visual alignment pass.

## Fixed

- Removed unsupported `MaxLines` attributes from `TextBlock` elements in `Carthago/Views/MainWindow.xaml`.
- Kept the intended one-line visual behavior by preserving:
  - `TextWrapping="NoWrap"`
  - `TextTrimming="CharacterEllipsis"`

## Reason

Classic WPF `TextBlock` in this target does not expose the `MaxLines` property, causing:

```text
MC3072: The property 'MaxLines' does not exist in XML namespace 'http://schemas.microsoft.com/winfx/2006/xaml/presentation'
```

## Scope

No runtime data behavior changed. The dashboard remains data-bound, settings-driven, and compatible with demo mode.
