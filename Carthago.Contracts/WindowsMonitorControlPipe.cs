// SPDX-License-Identifier: MIT
using System.IO.Pipes;
using System.Text.Json;

namespace Carthago.Contracts;

public static partial class WindowsLocalReadPipe
{
    private static string MonitorPipeName() => DefaultPipeName().Replace(".v1.", ".v4.", StringComparison.Ordinal);

    public static async Task<MonitorControlResponse> QueryMonitorAsync(MonitorControlRequest request,
        CancellationToken token, string? pipeName = null)
    {
        MonitorControlProtocol.ValidateRequest(request);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(Deadline);
        using var client = new NamedPipeClientStream(".", pipeName ?? MonitorPipeName(), PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await client.ConnectAsync(deadline.Token).ConfigureAwait(false);
        await LiveQueryProtocol.WriteAsync(client, request, LiveQueryProtocol.MaxRequestBytes, deadline.Token).ConfigureAwait(false);
        var response = await LiveQueryProtocol.ReadAsync<MonitorControlResponse>(client, LiveQueryProtocol.MaxResponseBytes,
            deadline.Token).ConfigureAwait(false);
        MonitorControlProtocol.ValidateResponse(response, request);
        await client.WriteAsync(new byte[] { LocalReadProtocol.Acknowledgment }, deadline.Token).ConfigureAwait(false);
        return response;
    }

    public static async Task ServeMonitorAsync(MonitorControlSession session, CancellationToken token, string? pipeName = null)
    {
        using var server = CreateLocalServer(pipeName ?? MonitorPipeName());
        while (!token.IsCancellationRequested)
        {
            await server.WaitForConnectionAsync(token).ConfigureAwait(false);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(Deadline);
            try
            {
                var request = await LiveQueryProtocol.ReadAsync<MonitorControlRequest>(server, LiveQueryProtocol.MaxRequestBytes,
                    deadline.Token).ConfigureAwait(false);
                var response = session.Query(request);
                MonitorControlProtocol.ValidateResponse(response, request);
                await LiveQueryProtocol.WriteAsync(server, response, LiveQueryProtocol.MaxResponseBytes, deadline.Token).ConfigureAwait(false);
                var acknowledgment = new byte[1];
                await server.ReadExactlyAsync(acknowledgment, deadline.Token).ConfigureAwait(false);
                if (acknowledgment[0] != LocalReadProtocol.Acknowledgment)
                    throw new InvalidDataException("Invalid acknowledgment.");
                session.CommitStop(request, response);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or OperationCanceledException)
            {
                // A malformed or disconnected client must not stop the monitor.
            }
            finally { server.Disconnect(); }
        }
    }
}
