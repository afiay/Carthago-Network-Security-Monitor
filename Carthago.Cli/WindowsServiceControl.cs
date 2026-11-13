// SPDX-License-Identifier: MIT
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Carthago.Cli;

public enum ScmState { Stopped = 1, StartPending = 2, StopPending = 3, Running = 4, ContinuePending = 5, PausePending = 6, Paused = 7 }
public sealed record ScmStatus(ScmState State, int ProcessId, int Win32ExitCode);
public interface IServiceControl
{
    ScmStatus Status();
    void Start();
    void Stop();
}

/// <summary>Fixed local service only. Windows SCM performs authorization.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsServiceControl : IServiceControl
{
    public const string ServiceName = "CarthagoMonitor";
    private const uint Connect = 0x0001, QueryStatus = 0x0004, StartAccess = 0x0010, StopAccess = 0x0020;

    public ScmStatus Status()
    {
        using var scm = OpenManager();
        using var service = Open(scm, QueryStatus);
        if (!QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<NativeStatus>(), out _))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if (!Enum.IsDefined((ScmState)status.CurrentState)) throw new InvalidDataException("Unknown SCM state.");
        return new((ScmState)status.CurrentState, status.ProcessId, status.Win32ExitCode);
    }

    public void Start()
    {
        using var scm = OpenManager();
        using var service = Open(scm, StartAccess);
        if (!StartService(service, 0, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public void Stop()
    {
        using var scm = OpenManager();
        using var service = Open(scm, StopAccess);
        if (!ControlService(service, 1, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    private static ServiceHandle OpenManager()
    {
        var handle = OpenSCManager(null, null, Connect);
        if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
        return handle;
    }

    private static ServiceHandle Open(ServiceHandle scm, uint access)
    {
        var handle = OpenService(scm, ServiceName, access);
        if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
        return handle;
    }

    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeStatus
    {
        public int ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode,
            CheckPoint, WaitHint, ProcessId, ServiceFlags;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeBasicStatus
    {
        public int ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint;
    }
    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenService(ServiceHandle scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(ServiceHandle service, int level, out NativeStatus status, int size, out int needed);
    [DllImport("advapi32.dll", EntryPoint = "StartServiceW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartService(ServiceHandle service, int count, IntPtr args);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(ServiceHandle service, uint control, out NativeBasicStatus status);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr service);
}
