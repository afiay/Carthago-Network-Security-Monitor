// SPDX-License-Identifier: MIT
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Carthago.Contracts;

/// <summary>Windows-only, same-account local pipe. No application identity attestation.</summary>
[SupportedOSPlatform("windows")]
public static partial class WindowsLocalReadPipe
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(5);

    public static string DefaultPipeName()
    {
        using var identity = WindowsIdentity.GetCurrent();
        string sid = identity.User?.Value ?? throw new InvalidOperationException("No user SID.");
        return "Carthago.Read.v1." + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sid)));
    }

    public static async Task<ReadResponse> QueryAsync(ReadCommand command, CancellationToken token,
        string? pipeName = null)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(Deadline);
        using var client = new NamedPipeClientStream(".", pipeName ?? DefaultPipeName(),
            PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await client.ConnectAsync(deadline.Token).ConfigureAwait(false);
        var request = new ReadRequest(command, Guid.NewGuid());
        await client.WriteAsync(LocalReadProtocol.EncodeRequest(request), deadline.Token).ConfigureAwait(false);
        var bytes = new byte[LocalReadProtocol.ResponseBytes];
        await client.ReadExactlyAsync(bytes, deadline.Token).ConfigureAwait(false);
        var response = LocalReadProtocol.DecodeResponse(bytes, request);
        await client.WriteAsync(new byte[] { LocalReadProtocol.Acknowledgment }, deadline.Token).ConfigureAwait(false);
        return response;
    }

    /// <summary>One connection at a time; one request per connection; no remote clients.</summary>
    public static async Task ServeAsync(Func<ReadRequest, ReadResponse> provider, CancellationToken token,
        string? pipeName = null)
    {
        ArgumentNullException.ThrowIfNull(provider);
        using var server = CreateLocalServer(pipeName ?? DefaultPipeName());
        while (!token.IsCancellationRequested)
        {
            await server.WaitForConnectionAsync(token).ConfigureAwait(false);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(Deadline);
            try
            {
                var bytes = new byte[LocalReadProtocol.RequestBytes];
                await server.ReadExactlyAsync(bytes, deadline.Token).ConfigureAwait(false);
                var request = LocalReadProtocol.DecodeRequest(bytes);
                ReadResponse response;
                try { response = provider(request); }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    response = new ReadResponse(request.Command, request.Correlation,
                        ReadState.Unavailable, 0, 0, 0, DateTimeOffset.UtcNow);
                }
                if (response.Command != request.Command || response.Correlation != request.Correlation)
                    throw new InvalidDataException("Provider response mismatch.");
                await server.WriteAsync(LocalReadProtocol.EncodeResponse(response), deadline.Token).ConfigureAwait(false);
                // DisconnectNamedPipe discards unread data. Wait until the client confirms
                // it read and validated the complete response; never wait beyond the deadline.
                var acknowledgment = new byte[1];
                await server.ReadExactlyAsync(acknowledgment, deadline.Token).ConfigureAwait(false);
                if (acknowledgment[0] != LocalReadProtocol.Acknowledgment)
                    throw new InvalidDataException("Invalid acknowledgment.");
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or OperationCanceledException)
            {
                // Malformed, disconnected or timed-out clients cannot terminate the host.
            }
            finally
            {
                // Disconnect also resets a broken pipe after a client exits early.
                server.Disconnect();
            }
        }
    }

    // .NET's standard named pipe constructor does not expose PIPE_REJECT_REMOTE_CLIENTS.
    // Create a Windows handle with that flag and a protected DACL for this exact SID.
    private static NamedPipeServerStream CreateLocalServer(string name)
    {
        using var identity = WindowsIdentity.GetCurrent();
        string sid = identity.User?.Value ?? throw new InvalidOperationException("No user SID.");
        string sddl = $"O:{sid}D:P(A;;GA;;;{sid})";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out var descriptor, out _))
            throw new IOException("Cannot create pipe security descriptor.");
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptor,
                InheritHandle = false
            };
            const uint Duplex = 3, Overlapped = 0x40000000, FirstInstance = 0x00080000;
            const uint RejectRemote = 0x00000008;
            var handle = CreateNamedPipe(@"\\.\pipe\" + name, Duplex | Overlapped | FirstInstance,
                RejectRemote, 1, 4096, 4096, 0, ref attributes);
            if (handle.IsInvalid)
            {
                handle.Dispose();
                throw new IOException("Cannot create local pipe.");
            }
            try { return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle); }
            catch { handle.Dispose(); throw; }
        }
        finally { LocalFree(descriptor); }
    }

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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateNamedPipeW")]
    private static extern SafePipeHandle CreateNamedPipe(string name, uint openMode, uint pipeMode,
        uint instances, uint outBuffer, uint inBuffer, uint timeout, ref SecurityAttributes attributes);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
