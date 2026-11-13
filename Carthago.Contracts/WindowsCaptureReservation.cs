// SPDX-License-Identifier: MIT
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Carthago.Contracts;

/// <summary>
/// Cooperative machine-wide reservation. Uses named mutex object existence, NOT
/// thread-affine mutex ownership. The last handle closing removes the reservation.
/// No elevation, waiting, or fallback to session-local names.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsCaptureReservation : IDisposable
{
    public const string DefaultName = @"Global\Carthago.Capture.Reservation.v1";
    private static readonly ConcurrentBag<SafeWaitHandle> Quarantined = new();
    private SafeWaitHandle? _handle;
    private WindowsCaptureReservation(SafeWaitHandle handle) => _handle = handle;

    public static WindowsCaptureReservation Acquire() => AcquireNamed(DefaultName);

    // Only for isolated qualification with a random name; production always uses DefaultName.
    public static WindowsCaptureReservation AcquireNamed(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || !name.StartsWith(@"Global\", StringComparison.Ordinal))
            throw new ArgumentException("Machine-wide reservation name required.", nameof(name));
        // Authenticated users can open an existing object only with SYNCHRONIZE;
        // no mutex ownership is ever acquired. SYSTEM/admin retain management access.
        const string sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;AU)";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out var descriptor, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Capture reservation security initialization failed.");
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptor
            };
            const uint Synchronize = 0x00100000;
            const int AlreadyExists = 183;
            var handle = CreateMutexEx(ref attributes, name, 0, Synchronize);
            int error = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                handle.Dispose();
                throw new Win32Exception(error, "Machine-wide capture reservation unavailable.");
            }
            if (error == AlreadyExists)
            {
                handle.Dispose();
                throw new InvalidOperationException("Another CARTHAGO capture owns the machine-wide reservation. Stop it before starting another.");
            }
            return new WindowsCaptureReservation(handle);
        }
        finally { LocalFree(descriptor); }
    }

    /// <summary>Retain reservation until process exit if native cleanup cannot be confirmed.</summary>
    public void Quarantine()
    {
        var handle = Interlocked.Exchange(ref _handle, null);
        if (handle is not null) Quarantined.Add(handle);
    }

    public void Dispose() => Interlocked.Exchange(ref _handle, null)?.Dispose();

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true,
        EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string text, uint revision, out IntPtr descriptor, out uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateMutexExW")]
    private static extern SafeWaitHandle CreateMutexEx(ref SecurityAttributes attributes, string name,
        uint flags, uint desiredAccess);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
