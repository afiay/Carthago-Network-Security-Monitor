// SPDX-License-Identifier: MIT
using System.IO.Pipes;
using System.Text.Json;

namespace Carthago.Contracts;

public static partial class WindowsLocalReadPipe
{
    private static string InvestigationPipeName() => DefaultPipeName().Replace(".v1.", ".v3.", StringComparison.Ordinal);

    public static async Task<InvestigationResponse> QueryInvestigationAsync(InvestigationRequest request, CancellationToken token,
        string? pipeName = null)
    {
        InvestigationProtocol.ValidateRequest(request);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(Deadline);
        using var client = new NamedPipeClientStream(".", pipeName ?? InvestigationPipeName(), PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await client.ConnectAsync(deadline.Token).ConfigureAwait(false);
        await LiveQueryProtocol.WriteAsync(client, request, LiveQueryProtocol.MaxRequestBytes, deadline.Token).ConfigureAwait(false);
        var response = await LiveQueryProtocol.ReadAsync<InvestigationResponse>(client, LiveQueryProtocol.MaxResponseBytes, deadline.Token).ConfigureAwait(false);
        InvestigationProtocol.ValidateResponse(response, request);
        await client.WriteAsync(new byte[] { LocalReadProtocol.Acknowledgment }, deadline.Token).ConfigureAwait(false);
        return response;
    }

    public static async Task ServeInvestigationAsync(Func<InvestigationRequest, CancellationToken, Task<InvestigationResponse>> provider,
        CancellationToken token, string? pipeName = null)
    {
        using var server = CreateLocalServer(pipeName ?? InvestigationPipeName());
        while (!token.IsCancellationRequested)
        {
            await server.WaitForConnectionAsync(token).ConfigureAwait(false);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(Deadline);
            try
            {
                var request = await LiveQueryProtocol.ReadAsync<InvestigationRequest>(server, LiveQueryProtocol.MaxRequestBytes, deadline.Token).ConfigureAwait(false);
                InvestigationProtocol.ValidateRequest(request);
                InvestigationResponse response;
                try { response = await provider(request, deadline.Token).ConfigureAwait(false); }
                catch (Exception ex) when (ex is not OutOfMemoryException && !deadline.IsCancellationRequested)
                {
                    response = new(InvestigationProtocol.Version, request.Correlation, request.Kind,
                        LiveQueryState.Unavailable, DateTimeOffset.UtcNow);
                }
                InvestigationProtocol.ValidateResponse(response, request);
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
