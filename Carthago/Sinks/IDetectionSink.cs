// SPDX-License-Identifier: MIT
// File: Sinks/IDetectionSink.cs
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Sinks
{
    public interface IDetectionSink : System.IDisposable
    {
        Task EmitAsync(DetectionEvent evt, CancellationToken ct = default);
    }
}
