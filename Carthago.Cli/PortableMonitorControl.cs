// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;
using Carthago.Services;

namespace Carthago.Cli;

/// <summary>Session-specific, same-user control. No discovery, PID targeting or Windows host IPC.</summary>
internal static class PortableMonitorControl
{
    internal enum Operation:byte { Status=1,Health=2,Stop=3 }
    private const int MaxResponseBytes=16384;
    private static readonly TimeSpan Timeout=TimeSpan.FromSeconds(2);
    private static readonly JsonSerializerOptions JsonOptions=new(JsonSerializerDefaults.Web);
    internal sealed record Response(int SchemaVersion,Guid SessionId,string Status,bool StopAllowed,
        DateTime ObservedUtc,string SourceHealth,string DetectionValidation,
        PortableMonitorSession.Snapshot? Monitor=null,PortableFrameQueue.Counters? Pipeline=null);

    internal static bool TryParse(string[] command,out Guid session,out Operation operation)
    {
        session=Guid.Empty;operation=default;
        if(command is not ["monitor",var action,"--session",var id]||
            !Guid.TryParseExact(id,"D",out session)||session==Guid.Empty)return false;
        operation=action switch
        { "portable-status"=>Operation.Status,"portable-health"=>Operation.Health,"portable-stop"=>Operation.Stop,_=>default };
        return operation!=default;
    }

    private static string Name(Guid session)=>"carthago-portable-"+session.ToString("N");
    internal static NamedPipeServerStream CreateServer(Guid session)
    {
        if(session==Guid.Empty)throw new ArgumentException("Session required.",nameof(session));
        return new NamedPipeServerStream(Name(session),PipeDirection.InOut,1,PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
    }

    private static Response Reply(Guid session,string status,bool allowStop,PortableBufferedCaptureRun.Progress? p=null)
        =>new(1,session,status,allowStop,DateTime.UtcNow,"not_assessed","not_assessed",p?.Monitor(),p?.Pipeline());

    // One connection at a time; one fixed-size request and bounded reply per connection.
    // A stalled or malformed client cannot hold the server indefinitely.
    internal static async Task ServeAsync(NamedPipeServerStream pipe,Guid session,PortableBufferedCaptureRun.Progress progress,
        bool allowStop,CancellationToken captureToken,Action requestStop,CancellationToken serverToken,Action failed)
    {
        using(pipe)
        {
            try
            {
                while(!serverToken.IsCancellationRequested)
                {
                    await pipe.WaitForConnectionAsync(serverToken).ConfigureAwait(false);
                    using var deadline=CancellationTokenSource.CreateLinkedTokenSource(serverToken);
                    deadline.CancelAfter(Timeout);
                    try
                    {
                        var request=new byte[18];
                        await pipe.ReadExactlyAsync(request.AsMemory(),deadline.Token).ConfigureAwait(false);
                        var target=new Guid(request.AsSpan(2,16));
                        var operation=(Operation)request[1];
                        if(request[0]!=1||target!=session||operation is not (Operation.Status or Operation.Health or Operation.Stop))
                            continue;
                        bool stopping=captureToken.IsCancellationRequested;
                        string status=stopping?"stopping":"running";
                        bool accept=operation==Operation.Stop&&allowStop&&!stopping;
                        if(operation==Operation.Stop)status=!allowStop?"stop_denied":accept?"stop_accepted":"stopping";
                        var response=Reply(session,status,allowStop,operation==Operation.Health?progress:null);
                        byte[] payload=JsonSerializer.SerializeToUtf8Bytes(response,JsonOptions);
                        if(payload.Length>MaxResponseBytes)throw new InvalidDataException("Control response too large.");
                        var prefix=new byte[4];BinaryPrimitives.WriteInt32LittleEndian(prefix,payload.Length);
                        await pipe.WriteAsync(prefix.AsMemory(),deadline.Token).ConfigureAwait(false);
                        await pipe.WriteAsync(payload.AsMemory(),deadline.Token).ConfigureAwait(false);
                        await pipe.FlushAsync(deadline.Token).ConfigureAwait(false);
                        // Acknowledge request before cancelling capture. This is not a
                        // confirmation that the monitor has drained or closed.
                        if(accept)requestStop();
                    }
                    catch(OperationCanceledException) when(deadline.IsCancellationRequested){}
                    catch(IOException){}
                    finally { if(pipe.IsConnected)pipe.Disconnect(); }
                }
            }
            catch(OperationCanceledException) when(serverToken.IsCancellationRequested){}
            catch(Exception ex) when(ex is not OutOfMemoryException)
            { if(!serverToken.IsCancellationRequested)failed(); }
        }
    }

    internal static async Task<Response> QueryAsync(Guid session,Operation operation,CancellationToken token)
    {
        if(session==Guid.Empty||operation is not (Operation.Status or Operation.Health or Operation.Stop))
            throw new ArgumentException("Valid session and operation required.");
        token.ThrowIfCancellationRequested();
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(Timeout);
        try
        {
            using var pipe=new NamedPipeClientStream(".",Name(session),PipeDirection.InOut,
                PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
            await pipe.ConnectAsync(deadline.Token).ConfigureAwait(false);
            var request=new byte[18];request[0]=1;request[1]=(byte)operation;
            session.TryWriteBytes(request.AsSpan(2));
            await pipe.WriteAsync(request.AsMemory(),deadline.Token).ConfigureAwait(false);
            await pipe.FlushAsync(deadline.Token).ConfigureAwait(false);
            var prefix=new byte[4];await pipe.ReadExactlyAsync(prefix.AsMemory(),deadline.Token).ConfigureAwait(false);
            int length=BinaryPrimitives.ReadInt32LittleEndian(prefix);
            if(length is <1 or >MaxResponseBytes)throw new InvalidDataException("Invalid control response length.");
            var payload=new byte[length];await pipe.ReadExactlyAsync(payload.AsMemory(),deadline.Token).ConfigureAwait(false);
            var response=JsonSerializer.Deserialize<Response>(payload,JsonOptions);
            if(response is null||response.SchemaVersion!=1||response.SessionId!=session||
                response.Status is not ("running" or "stopping" or "stop_denied" or "stop_accepted")||
                response.SourceHealth!="not_assessed"||response.DetectionValidation!="not_assessed"||
                (operation==Operation.Health&&(response.Monitor is null||response.Pipeline is null))||
                (operation!=Operation.Stop&&(response.Status is "stop_denied" or "stop_accepted")))
                throw new InvalidDataException("Invalid control response.");
            return response;
        }
        catch(OperationCanceledException) when(!token.IsCancellationRequested)
        { return Reply(session,"unavailable",false); }
        catch(Exception ex) when(ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        { return Reply(session,"unavailable",false); }
    }
}
