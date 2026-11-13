// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;

namespace Carthago.Cli;

/// <summary>Read-only pcap library/device discovery. Never opens or activates a capture handle.</summary>
internal static class NativeCaptureDiscovery
{
    internal sealed record Interface(string Id,bool Loopback);
    internal sealed record Result(string Provider,string LibraryStatus,string? LibraryVersion,
        string EnumerationStatus,string? Reason,IReadOnlyList<Interface> Interfaces);
    internal interface IApi : IDisposable
    {
        string? Version();
        IReadOnlyList<Interface> Enumerate();
    }

    internal static Result Discover() => Discover(OperatingSystem.IsWindows()?"wpcap":
        OperatingSystem.IsLinux()?"libpcap":"unsupported", Open);

    internal static Result Discover(string provider,Func<string,IApi?> open)
    {
        if(provider is not ("wpcap" or "libpcap"))
            return new("unsupported","unsupported",null,"not_attempted","unsupported_platform",Array.Empty<Interface>());
        IApi? api;
        try { api=open(provider); }
        catch(Exception ex) when(ex is not OutOfMemoryException)
        { return new(provider,"unavailable",null,"not_attempted","library_load_failed",Array.Empty<Interface>()); }
        if(api is null)
            return new(provider,"unavailable",null,"not_attempted","library_not_found_or_incompatible",Array.Empty<Interface>());
        using(api)
        {
            string? version=null;
            try
            {
                version=SafeText(api.Version(),256);
                var devices=api.Enumerate();
                if(devices.Count>256) throw new InvalidDataException();
                var seen=new HashSet<string>(StringComparer.Ordinal);
                var rows=new List<Interface>();
                foreach(var d in devices)
                {
                    var id=SafeText(d.Id,512);
                    // Never change the identifier that a later adapter must open.
                    if(id is null || !seen.Add(id)) throw new InvalidDataException();
                    rows.Add(new(id,d.Loopback));
                }
                return new(provider,"available",version,"succeeded",null,
                    rows.OrderBy(d=>d.Id,StringComparer.Ordinal).ToArray());
            }
            catch(Exception ex) when(ex is not OutOfMemoryException)
            { return new(provider,"available",version,"failed","interface_enumeration_failed",Array.Empty<Interface>()); }
        }
    }

    private static string? SafeText(string? value,int max) =>
        string.IsNullOrWhiteSpace(value)||value.Length>max||value.Any(c=>char.IsControl(c)||
            char.GetUnicodeCategory(c)==System.Globalization.UnicodeCategory.Format)?null:value;

    private static IApi? Open(string provider)
    {
        var handle=LoadHandle(provider);
        if(handle==IntPtr.Zero)return null;
        try { return new Api(handle); }
        catch { NativeLibrary.Free(handle);throw; }
    }

    internal static IntPtr LoadHandle(string provider)
    {
        IntPtr handle=IntPtr.Zero;
        if(provider=="wpcap")
        {
            // Absolute system paths, DLL directory and System32 dependencies only.
            // Prefer Npcap's normal installation over compatibility-mode wpcap.
            var system=Environment.SystemDirectory;
            foreach(var path in new[]{Path.Combine(system,"Npcap","wpcap.dll"),Path.Combine(system,"wpcap.dll")})
            {
                handle=LoadLibraryEx(path,IntPtr.Zero,0x00000100|0x00000800);
                if(handle!=IntPtr.Zero)break;
            }
        }
        else if(provider=="libpcap")
        {
            foreach(var soname in new[]{"libpcap.so.1","libpcap.so.0.8","libpcap.so"})
                if(NativeLibrary.TryLoad(soname,out handle))break;
        }
        return handle;
    }

    [DllImport("kernel32.dll",EntryPoint="LoadLibraryExW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern IntPtr LoadLibraryEx(string file,IntPtr reserved,uint flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct Device
    {
        internal IntPtr Next,Name,Description,Addresses;
        internal uint Flags;
    }
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr VersionFn();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int FindFn(out IntPtr devices,IntPtr error);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void FreeFn(IntPtr devices);

    private sealed class Api:IApi
    {
        private IntPtr _handle;
        private readonly VersionFn _version;
        private readonly FindFn _find;
        private readonly FreeFn _free;
        internal Api(IntPtr handle)
        {
            _handle=handle;
            _version=Marshal.GetDelegateForFunctionPointer<VersionFn>(NativeLibrary.GetExport(handle,"pcap_lib_version"));
            _find=Marshal.GetDelegateForFunctionPointer<FindFn>(NativeLibrary.GetExport(handle,"pcap_findalldevs"));
            _free=Marshal.GetDelegateForFunctionPointer<FreeFn>(NativeLibrary.GetExport(handle,"pcap_freealldevs"));
        }
        public string? Version()=>ReadString(_version(),256);
        public IReadOnlyList<Interface> Enumerate()
        {
            var error=Marshal.AllocHGlobal(256);
            IntPtr head=IntPtr.Zero;
            try
            {
                if(_find(out head,error)!=0)throw new InvalidOperationException();
                var rows=new List<Interface>();
                var seen=new HashSet<IntPtr>();
                for(var p=head;p!=IntPtr.Zero;)
                {
                    if(rows.Count>=256||!seen.Add(p))throw new InvalidDataException();
                    var d=Marshal.PtrToStructure<Device>(p);
                    var name=ReadString(d.Name,512)??throw new InvalidDataException();
                    rows.Add(new(name,(d.Flags&1u)!=0));
                    p=d.Next;
                }
                return rows;
            }
            finally
            {
                try { if(head!=IntPtr.Zero)_free(head); }
                finally { Marshal.FreeHGlobal(error); }
            }
        }
        private static string? ReadString(IntPtr pointer,int max)
        {
            if(pointer==IntPtr.Zero)return null;
            int length=0;
            while(length<=max && Marshal.ReadByte(pointer,length)!=0)length++;
            if(length>max)return null;
            // pcap names are OS-native identifiers; reject non-UTF8 rather than
            // silently replacing bytes and presenting a different identifier.
            var bytes=new byte[length];
            Marshal.Copy(pointer,bytes,0,length);
            return new System.Text.UTF8Encoding(false,true).GetString(bytes);
        }
        public void Dispose()
        {
            if(_handle==IntPtr.Zero)return;
            NativeLibrary.Free(_handle);_handle=IntPtr.Zero;
        }
    }
}
