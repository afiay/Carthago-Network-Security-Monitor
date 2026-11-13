// SPDX-License-Identifier: MIT
using System.IO.Pipes;
using System.Text.Json;

namespace Carthago.Contracts;

public static partial class WindowsLocalReadPipe
{
    private static string LivePipeName() => DefaultPipeName().Replace(".v1.", ".v2.", StringComparison.Ordinal);

    public static async Task<LiveQueryResult> QueryLiveAsync(LiveQuery request, CancellationToken token,
        string? pipeName = null)
    {
        LiveQueryProtocol.ValidateQuery(request);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(Deadline);
        using var client = new NamedPipeClientStream(".", pipeName ?? LivePipeName(), PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await client.ConnectAsync(deadline.Token).ConfigureAwait(false);
        await LiveQueryProtocol.WriteAsync(client, request, LiveQueryProtocol.MaxRequestBytes, deadline.Token).ConfigureAwait(false);
        var response = await LiveQueryProtocol.ReadAsync<LiveQueryResult>(client, LiveQueryProtocol.MaxResponseBytes, deadline.Token).ConfigureAwait(false);
        LiveQueryProtocol.ValidateResult(response, request);
        await client.WriteAsync(new byte[] { LocalReadProtocol.Acknowledgment }, deadline.Token).ConfigureAwait(false);
        return response;
    }

    public static async Task ServeLiveAsync(Func<LiveQuery, CancellationToken, Task<LiveQueryResult>> provider,
        CancellationToken token, string? pipeName = null)
    {
        using var server = CreateLocalServer(pipeName ?? LivePipeName());
        while (!token.IsCancellationRequested)
        {
            await server.WaitForConnectionAsync(token).ConfigureAwait(false);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(Deadline);
            try
            {
                var request = await LiveQueryProtocol.ReadAsync<LiveQuery>(server, LiveQueryProtocol.MaxRequestBytes, deadline.Token).ConfigureAwait(false);
                LiveQueryProtocol.ValidateQuery(request);
                LiveQueryResult response;
                try { response = await provider(request, deadline.Token).ConfigureAwait(false); }
                catch (Exception ex) when (ex is not OutOfMemoryException && !deadline.IsCancellationRequested)
                {
                    response = new(LiveQueryProtocol.Version, request.Correlation, request.Kind,
                        LiveQueryState.Unavailable, DateTimeOffset.UtcNow);
                }
                LiveQueryProtocol.ValidateResult(response, request);
                await LiveQueryProtocol.WriteAsync(server, response, LiveQueryProtocol.MaxResponseBytes, deadline.Token).ConfigureAwait(false);
                var ack = new byte[1];
                await server.ReadExactlyAsync(ack, deadline.Token).ConfigureAwait(false);
                if (ack[0] != LocalReadProtocol.Acknowledgment) throw new InvalidDataException("Invalid acknowledgment.");
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or OperationCanceledException)
            {
                // Reject malformed requests or interrupted connections; continue serving.
            }
            finally { server.Disconnect(); }
        }
    }
}
