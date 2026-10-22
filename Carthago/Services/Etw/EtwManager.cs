// SPDX-License-Identifier: MIT
// File: Services/Etw/EtwManager.cs
//
// Small coordinator so UI and TrafficCaptureService can toggle ETW without tight coupling.

using System;
using System.Threading;
using System.Threading.Channels;
using Carthago.Models;

namespace Carthago.Services.Etw
{
    public static class EtwManager
    {
        private static MsQuicEtwListener? _msquic;
        private static TcpIpEtwListener? _tcpip;
        private static ChannelWriter<TrafficRecord>? _writer;
        private static CancellationToken _cancel;

        public static void Initialize(ChannelWriter<TrafficRecord> writer, CancellationToken cancel)
        {
            _writer = writer;
            _cancel = cancel;
        }

        public static bool MsQuicEnabled => _msquic?.IsRunning == true;
        public static bool TcpIpEnabled => _tcpip?.IsRunning == true;

        public static void SetMsQuic(bool enable)
        {
            if (_writer == null) return;
            if (enable)
            {
                _msquic ??= new MsQuicEtwListener();
                _msquic.Start(_writer, _cancel);
            }
            else
            {
                _msquic?.Stop();
                _msquic = null;
            }
        }

        public static void SetTcpIp(bool enable)
        {
            if (enable)
            {
                _tcpip ??= new TcpIpEtwListener();
                _tcpip.Start(_cancel);
            }
            else
            {
                _tcpip?.Stop();
                _tcpip = null;
            }
        }

        public static void StopAll()
        {
            try { _msquic?.Stop(); } catch { }
            try { _tcpip?.Stop(); } catch { }
            _msquic = null;
            _tcpip = null;
        }
    }
}
