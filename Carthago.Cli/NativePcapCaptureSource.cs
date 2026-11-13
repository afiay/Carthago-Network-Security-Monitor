// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using Carthago.Services;

namespace Carthago.Cli;

/// <summary>Single-owner native pcap adapter. Not wired to a public live-start command.</summary>
internal sealed class NativePcapCaptureSource : IPortableCaptureSource
{
    internal const int SnapLength=262144;
    internal const int PollMilliseconds=10;
    internal interface IApi:IDisposable
    {
        int Open(string interfaceId);
        // 1 packet, 0 no packet, -2 EOF, -1 error. Own packet bytes on return.
        int Next(out PortableCaptureFrame? frame);
        DriverStatistics ReadStatistics() => DriverStatistics.Unavailable;
        void Close();
    }

    // Raw provider counters, not reconciled with managed frame counts.
    internal sealed record DriverStatistics(string Status,uint? Received,uint? BufferDropped,uint? InterfaceDropped,
        string InterfaceDropMeaning)
    {
        internal static readonly DriverStatistics Unavailable=new("unavailable",null,null,null,"not_assessed");
        internal static readonly DriverStatistics NotAttempted=new("not_attempted",null,null,null,"not_assessed");
    }
    internal DriverStatistics FinalStatistics { get; private set; }=DriverStatistics.NotAttempted;

    private readonly string _id;
    private readonly Func<IApi> _factory;
    private IApi? _api;
    private bool _started,_stopped,_disposed;

    internal NativePcapCaptureSource(string interfaceId,Func<IApi>? factory=null)
    {
        if(string.IsNullOrWhiteSpace(interfaceId)||interfaceId.Length>512||
            interfaceId.Any(c=>char.IsControl(c)||char.GetUnicodeCategory(c)==System.Globalization.UnicodeCategory.Format)||
            interfaceId.Contains("://",StringComparison.Ordinal))
            throw new ArgumentException("Explicit local interface identifier required.",nameof(interfaceId));
        _id=interfaceId;_factory=factory??OpenNativeApi;
    }

    public ValueTask<int> StartAsync(CancellationToken token)
    {
        if(_disposed||_stopped||_api is not null)throw new InvalidOperationException("Source cannot be restarted.");
        token.ThrowIfCancellationRequested();
        _api=_factory();
        int link=_api.Open(_id);
        if(link is not (0 or 1 or 12 or 101 or 113 or 228 or 229 or 276))
            throw new InvalidDataException("Unsupported native link type.");
        token.ThrowIfCancellationRequested();
        _started=true;
        return ValueTask.FromResult(link);
    }

    public async ValueTask<PortableCaptureFrame?> ReadAsync(CancellationToken token)
    {
        if(!_started||_stopped||_disposed||_api is null)throw new InvalidOperationException("Source not started.");
        while(true)
        {
            token.ThrowIfCancellationRequested();
            int code=_api.Next(out var frame);
            if(code==1)
                return frame??throw new InvalidDataException("Native packet missing.");
            if(code==-2)return null;
            if(code!=0)throw new InvalidOperationException("Native read failed.");
            await Task.Delay(PollMilliseconds,token).ConfigureAwait(false);
        }
    }

    public ValueTask StopAsync()
    {
        if(_stopped)return ValueTask.CompletedTask;
        FinishCapture();
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        if(_disposed)return ValueTask.CompletedTask;
        _disposed=true;
        try { if(!_stopped)FinishCapture(); }
        finally { _api?.Dispose();_api=null; }
        return ValueTask.CompletedTask;
    }

    private void FinishCapture()
    {
        _stopped=true;
        try
        {
            if(_started && _api is not null)
            {
                try { FinalStatistics=_api.ReadStatistics(); }
                catch(Exception ex) when(ex is not OutOfMemoryException)
                { FinalStatistics=DriverStatistics.Unavailable; }
            }
        }
        finally { _started=false;_api?.Close(); }
    }

    internal static DriverStatistics DecodeStatistics(IntPtr buffer,bool windows)
    {
        if(buffer==IntPtr.Zero)throw new ArgumentException("Statistics buffer required.",nameof(buffer));
        uint recv=unchecked((uint)Marshal.ReadInt32(buffer,0));
        uint drop=unchecked((uint)Marshal.ReadInt32(buffer,4));
        uint ifdrop=unchecked((uint)Marshal.ReadInt32(buffer,8));
        // Npcap does not implement ps_ifdrop. Linux zero is ambiguous.
        return new("available",recv,drop,windows?null:ifdrop,
            windows?"not_reported_on_windows":"provider_dependent_zero_may_be_unavailable");
    }

    private static IApi OpenNativeApi()
    {
        // Windows timeval has two 32-bit longs; 64-bit Linux uses two 64-bit
        // longs. Refuse other ABIs until their header layout is qualified.
        if(!BitConverter.IsLittleEndian||!Environment.Is64BitProcess||
            RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64)||
            !(OperatingSystem.IsWindows()||OperatingSystem.IsLinux()))
            throw new PlatformNotSupportedException("Unsupported native capture ABI.");
        var handle=NativeCaptureDiscovery.LoadHandle(OperatingSystem.IsWindows()?"wpcap":"libpcap");
        if(handle==IntPtr.Zero)throw new InvalidOperationException("Capture library unavailable.");
        try { return new Api(handle,OperatingSystem.IsWindows()); }
        catch { NativeLibrary.Free(handle);throw; }
    }

    // Decode native pcap_pkthdr only after successful pcap_next_ex. Never read
    // packet memory until captured length and timestamp have passed validation.
    internal static PortableCaptureFrame DecodePacket(IntPtr header,IntPtr data,bool windows)
    {
        if(header==IntPtr.Zero)throw new InvalidDataException("Native header missing.");
        long seconds=windows?Marshal.ReadInt32(header,0):Marshal.ReadInt64(header,0);
        long micros=windows?Marshal.ReadInt32(header,4):Marshal.ReadInt64(header,8);
        int offset=windows?8:16;
        uint captured=unchecked((uint)Marshal.ReadInt32(header,offset));
        uint original=unchecked((uint)Marshal.ReadInt32(header,offset+4));
        if(seconds<0||seconds>253402300799L||micros is <0 or >=1000000||
            captured>SnapLength||captured>original||(captured!=0&&data==IntPtr.Zero))
            throw new InvalidDataException("Invalid native packet metadata.");
        var bytes=new byte[(int)captured];
        if(bytes.Length!=0)Marshal.Copy(data,bytes,0,bytes.Length);
        var timestamp=DateTime.UnixEpoch.AddSeconds(seconds).AddTicks(micros*10);
        return new(bytes,original,timestamp);
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr CreateFn([MarshalAs(UnmanagedType.LPUTF8Str)] string id,IntPtr error);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int SetFn(IntPtr handle,int value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int ActivateFn(IntPtr handle);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int NonblockFn(IntPtr handle,int value,IntPtr error);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int NextFn(IntPtr handle,out IntPtr header,out IntPtr data);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void CloseFn(IntPtr handle);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int StatsFn(IntPtr handle,IntPtr buffer);

    private sealed class Api:IApi
    {
        private IntPtr _library,_capture;
        private readonly bool _windows;
        private readonly CreateFn _create;
        private readonly SetFn _snap,_promisc,_timeout,_precision;
        private readonly ActivateFn _activate,_link;
        private readonly NonblockFn _nonblock;
        private readonly NextFn _next;
        private readonly CloseFn _close;
        private readonly StatsFn? _stats;

        internal Api(IntPtr library,bool windows)
        {
            _library=library;_windows=windows;
            T Export<T>(string name) where T:Delegate =>
                Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library,name));
            _create=Export<CreateFn>("pcap_create");
            _snap=Export<SetFn>("pcap_set_snaplen");
            _promisc=Export<SetFn>("pcap_set_promisc");
            _timeout=Export<SetFn>("pcap_set_timeout");
            _precision=Export<SetFn>("pcap_set_tstamp_precision");
            _activate=Export<ActivateFn>("pcap_activate");
            _link=Export<ActivateFn>("pcap_datalink");
            _nonblock=Export<NonblockFn>("pcap_setnonblock");
            _next=Export<NextFn>("pcap_next_ex");
            _close=Export<CloseFn>("pcap_close");
            if(NativeLibrary.TryGetExport(library,"pcap_stats",out var stats))
                _stats=Marshal.GetDelegateForFunctionPointer<StatsFn>(stats);
        }
        public int Open(string interfaceId)
        {
            var error=Marshal.AllocHGlobal(256);
            try
            {
                _capture=_create(interfaceId,error);
                if(_capture==IntPtr.Zero)throw new InvalidOperationException("Native capture create failed.");
                // No promisc, monitor mode, remote source, or privilege elevation.
                // Explicit microsecond timestamp precision and nonblocking reads.
                if(_snap(_capture,SnapLength)!=0||_promisc(_capture,0)!=0||
                    _timeout(_capture,100)!=0||_precision(_capture,0)!=0||
                    _activate(_capture)!=0||_nonblock(_capture,1,error)!=0)
                    throw new InvalidOperationException("Native capture activation failed.");
                return _link(_capture);
            }
            finally { Marshal.FreeHGlobal(error); }
        }
        public int Next(out PortableCaptureFrame? frame)
        {
            frame=null;
            int code=_next(_capture,out var header,out var data);
            if(code==1)frame=DecodePacket(header,data,_windows);
            return code;
        }
        public DriverStatistics ReadStatistics()
        {
            if(_capture==IntPtr.Zero||_stats is null)return DriverStatistics.Unavailable;
            // Windows pcap_stat has six uint fields; Linux has three. Reserve all six.
            var buffer=Marshal.AllocHGlobal(24);
            try
            {
                Marshal.Copy(new byte[24],0,buffer,24);
                return _stats(_capture,buffer)==0?DecodeStatistics(buffer,_windows):DriverStatistics.Unavailable;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        public void Close()
        {
            if(_capture==IntPtr.Zero)return;
            var handle=_capture;_capture=IntPtr.Zero;_close(handle);
        }
        public void Dispose()
        {
            try { Close(); }
            finally
            {
                if(_library!=IntPtr.Zero){NativeLibrary.Free(_library);_library=IntPtr.Zero;}
            }
        }
    }
}
