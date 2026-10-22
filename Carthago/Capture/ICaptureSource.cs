// File: Capture/ICaptureSource.cs
// SPDX-License-Identifier: MIT

using System;
using System.Threading.Tasks;

namespace Carthago.Capture
{
    /// <summary>
    /// Generic capture source abstraction for pluggable backends
    /// (Npcap, ETW, WinDivert, etc.). 
    /// </summary>
    public interface ICaptureSource : IDisposable
    {
        string Name { get; }
        bool IsRunning { get; }

        /// <summary>Start asynchronous capture loop.</summary>
        Task StartAsync();

        /// <summary>Stop capture loop gracefully.</summary>
        Task StopAsync();
    }
}
