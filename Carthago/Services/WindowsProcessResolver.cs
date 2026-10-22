// File: Services/WindowsProcessResolver.cs
// SPDX-License-Identifier: MIT

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Carthago.Services
{
    /// <summary>
    /// Windows process resolver:
    /// - IPv4 + IPv6 (TCP/UDP) via GetExtended*Table P/Invoke
    /// - Correct network-byte-order port decoding
    /// - Disambiguates by remote endpoint for TCP when available
    /// - TTL cache with per-key invalidation
    /// - Optional Authenticode verification (fast presence check by default;
    ///   optional full WinVerifyTrust can be added later)
    /// </summary>
    public static class WindowsProcessResolver
    {
        public sealed class ProcessInfo
        {
            public int ProcessId { get; set; }
            public string ProcessName { get; set; } = "Unknown";
            public string ExecutablePath { get; set; } = "Unknown";
            public DateTime? StartTime { get; set; }
            public bool? IsSigned { get; set; }
            public string SignatureStatus { get; set; } = "Unknown";
            public string Signer { get; set; } = "Unknown";
        }

        /// <summary>Enable/disable Authenticode presence check (opening image cert). Default false.</summary>
        public static bool CheckSignature { get; set; } = false;

        /// <summary>Per-key TTL (avoid table scans every packet). Default 20s is reasonable under load.</summary>
        public static TimeSpan CacheTtl { get; set; } = TimeSpan.FromSeconds(20);

        private sealed class CacheEntry
        {
            public ProcessInfo Info { get; init; } = new();
            public DateTimeOffset Expires { get; init; }
            public bool Fresh => DateTimeOffset.UtcNow < Expires;
        }

        // key: proto:localPort:localAddr|*:[remoteAddr|*]:[remotePort|*]
        private static readonly ConcurrentDictionary<string, CacheEntry> Cache = new();

        /// <summary>
        /// Best-effort resolution for the packet tuple.
        /// We try outbound (src as local) first, then inbound (dst as local).
        /// For TCP, we attempt to match both local and remote endpoints to disambiguate.
        /// </summary>
        public static ProcessInfo? ResolveProcess(
            string sourceIP, int? sourcePort,
            string destIP, int? destPort,
            string protocol)
        {
            try
            {
                var proto = (protocol ?? "TCP").ToUpperInvariant();

                // Candidate order: outbound (src local), then inbound (dst local)
                var candidates = new[]
                {
                    new Candidate(proto, sourceIP, sourcePort, destIP, destPort),
                    new Candidate(proto, destIP,   destPort,   sourceIP, sourcePort)
                };

                foreach (var c in candidates)
                {
                    if (!c.LocalPort.HasValue || c.LocalPort.Value <= 0) continue;

                    var key = c.MakeKey();
                    if (TryGetFresh(key, out var pi)) return pi;

                    int pid = c.Proto switch
                    {
                        "TCP" => FindPidTcp(c),
                        "UDP" => FindPidUdp(c),
                        _ => 0
                    };

                    var info = BuildProcessInfo(pid);
                    SetCache(key, info);
                    if (pid > 0) return info;
                }

                return null;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[WindowsProcessResolver] Resolve error: {ex}");
                return null;
            }
        }

        public static void ClearCache() => Cache.Clear();

        public static void Invalidate(string protocol, int localPort, string? localAddr = null, string? remoteAddr = null, int? remotePort = null)
        {
            var proto = (protocol ?? "TCP").ToUpperInvariant();
            var key = new Candidate(proto, localAddr, localPort, remoteAddr, remotePort).MakeKey();
            Cache.TryRemove(key, out _);
        }

        // ---------------- internal ----------------

        private static bool TryGetFresh(string key, out ProcessInfo? info)
        {
            info = null;
            if (Cache.TryGetValue(key, out var ce) && ce.Fresh)
            {
                info = ce.Info;
                return true;
            }
            return false;
        }

        private static void SetCache(string key, ProcessInfo info)
        {
            Cache[key] = new CacheEntry
            {
                Info = info,
                Expires = DateTimeOffset.UtcNow.Add(CacheTtl)
            };
        }

        private readonly struct Candidate
        {
            public string Proto { get; }
            public string? LocalAddr { get; }
            public int? LocalPort { get; }
            public string? RemoteAddr { get; }
            public int? RemotePort { get; }

            public Candidate(string proto, string? localAddr, int? localPort, string? remoteAddr, int? remotePort)
            {
                Proto = proto;
                LocalAddr = localAddr;
                LocalPort = localPort;
                RemoteAddr = remoteAddr;
                RemotePort = remotePort;
            }

            public string MakeKey()
            {
                string la = string.IsNullOrWhiteSpace(LocalAddr) ? "*" : LocalAddr!;
                string ra = string.IsNullOrWhiteSpace(RemoteAddr) ? "*" : RemoteAddr!;
                string lp = (LocalPort ?? 0).ToString();
                string rp = (RemotePort ?? 0).ToString();
                return $"{Proto}:{lp}:{la}:{ra}:{rp}";
            }
        }

        private static int FindPidTcp(Candidate c)
        {
            // v4 first, then v6; exact match by local (and remote if available)
            if (TryFindPidInTcpTable(AddressFamily.InterNetwork, c, out int pid4)) return pid4;
            if (TryFindPidInTcp6Table(c, out int pid6)) return pid6;
            return 0;
        }

        private static int FindPidUdp(Candidate c)
        {
            // UDP tables have no remote info; match by local addr/port only
            if (TryFindPidInUdpTable(AddressFamily.InterNetwork, c, out int pid4)) return pid4;
            if (TryFindPidInUdp6Table(c, out int pid6)) return pid6;
            return 0;
        }

        // ---------- TCPv4 ----------

        private static bool TryFindPidInTcpTable(AddressFamily af, Candidate c, out int pid)
        {
            pid = 0;
            int size = 0;
            IntPtr tablePtr = IntPtr.Zero;

            try
            {
                GetExtendedTcpTable(IntPtr.Zero, ref size, true, (int)af, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                tablePtr = Marshal.AllocHGlobal(size);

                if (GetExtendedTcpTable(tablePtr, ref size, true, (int)af, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                    return false;

                int num = Marshal.ReadInt32(tablePtr);
                IntPtr rowPtr = IntPtr.Add(tablePtr, 4);

                int partialPid = 0;
                for (int i = 0; i < num; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                    int lport = ReadPort(row.localPort);
                    if (lport != c.LocalPort) { rowPtr = Next<MIB_TCPROW_OWNER_PID>(rowPtr); continue; }

                    var laddr = new IPAddress(row.localAddr);
                    if (!AddrOk(c.LocalAddr, laddr)) { rowPtr = Next<MIB_TCPROW_OWNER_PID>(rowPtr); continue; }

                    // remote disambiguation if caller provided
                    bool remoteOk = true;
                    if (c.RemotePort.HasValue && c.RemotePort.Value > 0)
                        remoteOk = ReadPort(row.remotePort) == c.RemotePort.Value;
                    if (remoteOk && !string.IsNullOrWhiteSpace(c.RemoteAddr))
                        remoteOk = TryParseIp(c.RemoteAddr!, out var wantR) && wantR.Equals(new IPAddress(row.remoteAddr));

                    if (remoteOk)
                    {
                        pid = row.owningPid;
                        return pid > 0;
                    }

                    // keep as fallback if we didn't find a remote-exact match
                    if (partialPid == 0) partialPid = row.owningPid;

                    rowPtr = Next<MIB_TCPROW_OWNER_PID>(rowPtr);
                }

                pid = partialPid;
                return pid > 0;
            }
            catch
            {
                pid = 0; return false;
            }
            finally
            {
                if (tablePtr != IntPtr.Zero) Marshal.FreeHGlobal(tablePtr);
            }
        }

        // ---------- TCPv6 ----------

        private static bool TryFindPidInTcp6Table(Candidate c, out int pid)
        {
            pid = 0;
            int size = 0;
            IntPtr tablePtr = IntPtr.Zero;

            try
            {
                GetExtendedTcpTable(IntPtr.Zero, ref size, true, (int)AddressFamily.InterNetworkV6, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                tablePtr = Marshal.AllocHGlobal(size);

                if (GetExtendedTcpTable(tablePtr, ref size, true, (int)AddressFamily.InterNetworkV6, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                    return false;

                int num = Marshal.ReadInt32(tablePtr);
                IntPtr rowPtr = IntPtr.Add(tablePtr, 4);

                int partialPid = 0;
                for (int i = 0; i < num; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                    int lport = ReadPort(row.localPort);
                    if (lport != c.LocalPort) { rowPtr = Next<MIB_TCP6ROW_OWNER_PID>(rowPtr); continue; }

                    var laddr = new IPAddress(row.localAddr, row.localScopeId);
                    if (!AddrOk(c.LocalAddr, laddr)) { rowPtr = Next<MIB_TCP6ROW_OWNER_PID>(rowPtr); continue; }

                    bool remoteOk = true;
                    if (c.RemotePort.HasValue && c.RemotePort.Value > 0)
                        remoteOk = ReadPort(row.remotePort) == c.RemotePort.Value;
                    if (remoteOk && !string.IsNullOrWhiteSpace(c.RemoteAddr))
                        remoteOk = TryParseIp(c.RemoteAddr!, out var wantR) && wantR.Equals(new IPAddress(row.remoteAddr, row.remoteScopeId));

                    if (remoteOk)
                    {
                        pid = (int)row.owningPid;
                        return pid > 0;
                    }

                    if (partialPid == 0) partialPid = (int)row.owningPid;
                    rowPtr = Next<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                }

                pid = partialPid;
                return pid > 0;
            }
            catch
            {
                pid = 0; return false;
            }
            finally
            {
                if (tablePtr != IntPtr.Zero) Marshal.FreeHGlobal(tablePtr);
            }
        }

        // ---------- UDPv4 ----------

        private static bool TryFindPidInUdpTable(AddressFamily af, Candidate c, out int pid)
        {
            pid = 0;
            int size = 0;
            IntPtr tablePtr = IntPtr.Zero;

            try
            {
                GetExtendedUdpTable(IntPtr.Zero, ref size, true, (int)af, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                tablePtr = Marshal.AllocHGlobal(size);

                if (GetExtendedUdpTable(tablePtr, ref size, true, (int)af, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0) != 0)
                    return false;

                int num = Marshal.ReadInt32(tablePtr);
                IntPtr rowPtr = IntPtr.Add(tablePtr, 4);

                int partialPid = 0;
                for (int i = 0; i < num; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                    int lport = ReadPort(row.localPort);
                    if (lport != c.LocalPort) { rowPtr = Next<MIB_UDPROW_OWNER_PID>(rowPtr); continue; }

                    var laddr = new IPAddress(row.localAddr);
                    if (!AddrOk(c.LocalAddr, laddr)) { rowPtr = Next<MIB_UDPROW_OWNER_PID>(rowPtr); continue; }

                    pid = row.owningPid;
                    return pid > 0;
                }

                pid = partialPid;
                return pid > 0;
            }
            catch
            {
                pid = 0; return false;
            }
            finally
            {
                if (tablePtr != IntPtr.Zero) Marshal.FreeHGlobal(tablePtr);
            }
        }

        // ---------- UDPv6 ----------

        private static bool TryFindPidInUdp6Table(Candidate c, out int pid)
        {
            pid = 0;
            int size = 0;
            IntPtr tablePtr = IntPtr.Zero;

            try
            {
                GetExtendedUdpTable(IntPtr.Zero, ref size, true, (int)AddressFamily.InterNetworkV6, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                tablePtr = Marshal.AllocHGlobal(size);

                if (GetExtendedUdpTable(tablePtr, ref size, true, (int)AddressFamily.InterNetworkV6, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0) != 0)
                    return false;

                int num = Marshal.ReadInt32(tablePtr);
                IntPtr rowPtr = IntPtr.Add(tablePtr, 4);

                for (int i = 0; i < num; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);
                    int lport = ReadPort(row.localPort);
                    if (lport != c.LocalPort) { rowPtr = Next<MIB_UDP6ROW_OWNER_PID>(rowPtr); continue; }

                    var laddr = new IPAddress(row.localAddr, row.localScopeId);
                    if (!AddrOk(c.LocalAddr, laddr)) { rowPtr = Next<MIB_UDP6ROW_OWNER_PID>(rowPtr); continue; }

                    pid = (int)row.owningPid;
                    return pid > 0;
                }

                return false;
            }
            catch
            {
                pid = 0; return false;
            }
            finally
            {
                if (tablePtr != IntPtr.Zero) Marshal.FreeHGlobal(tablePtr);
            }
        }

        // ---------- helpers ----------

        private static bool AddrOk(string? preferredLocalAddr, IPAddress candidate)
        {
            if (string.IsNullOrWhiteSpace(preferredLocalAddr)) return true;
            if (!TryParseIp(preferredLocalAddr, out var want)) return true; // ignore preference on parse failure
            if (want.AddressFamily != candidate.AddressFamily) return false;
            return want.Equals(candidate);
        }

        private static bool TryParseIp(string s, out IPAddress ip) => IPAddress.TryParse(s, out ip!);

        private static IntPtr Next<T>(IntPtr ptr) => IntPtr.Add(ptr, Marshal.SizeOf(typeof(T)));

        private static int ReadPort(byte[] networkOrderFourBytes)
        {
            if (networkOrderFourBytes is null || networkOrderFourBytes.Length < 2) return 0;
            return BinaryPrimitives.ReadUInt16BigEndian(new ReadOnlySpan<byte>(networkOrderFourBytes, 0, 2));
        }

        private static ProcessInfo BuildProcessInfo(int pid)
        {
            if (pid <= 0)
                return new ProcessInfo { ProcessId = pid, ProcessName = "Unknown" };

            try
            {
                using var p = Process.GetProcessById(pid);
                var info = new ProcessInfo
                {
                    ProcessId = pid,
                    ProcessName = Safe(() => p.ProcessName, "Unknown"),
                    ExecutablePath = Safe(() => p.MainModule?.FileName ?? "Unknown", "Unknown"),
                    StartTime = Safe<DateTime?>(() => p.StartTime, null)
                };

                if (CheckSignature && !string.IsNullOrWhiteSpace(info.ExecutablePath) && info.ExecutablePath != "Unknown")
                {
                    try
                    {
                        using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(info.ExecutablePath));
                        info.IsSigned = cert != null;
                        info.Signer = cert?.GetNameInfo(X509NameType.SimpleName, false) ?? "Unknown";
                        info.SignatureStatus = info.IsSigned == true ? "Signed" : "Unsigned";
                    }
                    catch (CryptographicException)
                    {
                        info.IsSigned = false;
                        info.SignatureStatus = "Unsigned";
                    }
                    catch
                    {
                        info.IsSigned = null;
                        info.SignatureStatus = "Unknown";
                    }
                }

                return info;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[WindowsProcessResolver] BuildProcessInfo error: {ex}");
                return new ProcessInfo { ProcessId = pid, ProcessName = "Unknown" };
            }
        }

        private static T Safe<T>(Func<T> f, T fallback)
        {
            try { return f(); } catch { return fallback; }
        }

        // ---------- P/Invoke ----------

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            TCP_TABLE_CLASS TableClass,
            uint Reserved = 0);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(
            IntPtr pUdpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            UDP_TABLE_CLASS TableClass,
            uint Reserved = 0);

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_OWNER_PID_ALL = 5
        }

        private enum UDP_TABLE_CLASS
        {
            UDP_TABLE_OWNER_PID = 1
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] localPort;
            public uint remoteAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] remotePort;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] localPort;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr; // in6_addr
            public uint localScopeId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] localPort;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] remoteAddr; // in6_addr
            public uint remoteScopeId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] remotePort;

            public uint state;
            public uint owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr; // in6_addr
            public uint localScopeId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] localPort;
            public uint owningPid;
        }
    }
}
