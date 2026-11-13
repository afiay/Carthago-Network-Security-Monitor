// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text;
using System.Text.Json;
using Carthago.Engine.Rules;

namespace Carthago.Cli;

/// <summary>Single writer, session-owned rotating evidence. No raw packets or external log ingestion.</summary>
internal sealed class PortableMonitorJournal:IDisposable
{
    internal const int DefaultSegmentBytes=1048576,DefaultSegments=4,MaxSegmentBytes=4194304,MaxSegments=8;
    private const int MaxRecordBytes=16384;
    private readonly int _segmentBytes,_retain;
    private readonly Queue<string> _owned=new();
    private FileStream? _stream;
    private long _segment;
    internal string DirectoryPath { get; }
    private static readonly UTF8Encoding Utf8=new(false,true);
    internal sealed record Finding(long Sequence,long PacketNumber,DateTime TimestampUtc,string RuleId,string Method);
    internal sealed record Summary(Guid SessionId,string Status,bool RetentionGap,bool PartialTail,long Records,
        long FindingCount,long? FirstSequence,long? LastSequence,IReadOnlyList<Finding> Findings);

    internal static bool ValidPath(string value)=>!string.IsNullOrWhiteSpace(value)&&value.Length<=4096&&
        !value.StartsWith("--",StringComparison.Ordinal)&&!value.Any(char.IsControl);

    internal PortableMonitorJournal(string root,Guid session,int segmentBytes=DefaultSegmentBytes,int retain=DefaultSegments)
    {
        if(session==Guid.Empty||!ValidPath(root)||segmentBytes is <256 or >MaxSegmentBytes||retain is <1 or >MaxSegments)
            throw new ArgumentException("Invalid journal configuration.");
        // Root must be explicitly provisioned by operator. Never delete other sessions.
        if(!Directory.Exists(root))throw new DirectoryNotFoundException("Journal root must exist.");
        DirectoryPath=Path.Combine(Path.GetFullPath(root),session.ToString("D"));
        if(Directory.Exists(DirectoryPath)||File.Exists(DirectoryPath))throw new IOException("Journal session already exists.");
        if(OperatingSystem.IsWindows())Directory.CreateDirectory(DirectoryPath);
        else Directory.CreateDirectory(DirectoryPath,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        _segmentBytes=segmentBytes;_retain=retain;
    }

    internal void Append(string line)
    {
        var bytes=Utf8.GetBytes(line+"\n");
        if(bytes.Length>MaxRecordBytes||bytes.Length>_segmentBytes)throw new InvalidDataException("Journal record too large.");
        if(_stream is null||_stream.Length+bytes.Length>_segmentBytes)
        {
            _stream?.Dispose();_stream=null;
            if(_owned.Count==_retain){File.Delete(_owned.Peek());_owned.Dequeue();}
            var path=Path.Combine(DirectoryPath,$"segment-{++_segment:D12}.ndjson");
            var options=new FileStreamOptions { Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None };
            if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
            _stream=new FileStream(path,options);_owned.Enqueue(path);
        }
        _stream.Write(bytes);
        _stream.Flush(flushToDisk:true);
    }

    public void Dispose(){_stream?.Dispose();_stream=null;}

    internal static bool TryParse(string[] command,out string directory,out int limit)
    {
        directory="";limit=50;
        if(command.Length is not (3 or 5)||command[0]!="monitor"||command[1]!="journal"||!ValidPath(command[2]))return false;
        if(command.Length==5&&(command[3]!="--limit"||!int.TryParse(command[4],NumberStyles.None,
            CultureInfo.InvariantCulture,out limit)||limit is <1 or >100))return false;
        directory=command[2];return true;
    }

    // Inspect a closed or abandoned session only; active writer denies sharing.
    // Imported data is untrusted. Return only validated projected fields.
    internal static Summary Inspect(string directory,int limit,CancellationToken token)
    {
        if(limit is <1 or >100)throw new ArgumentOutOfRangeException(nameof(limit));
        var full=Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        if(!Guid.TryParseExact(Path.GetFileName(full),"D",out var session)||session==Guid.Empty)
            throw new InvalidDataException("Expected session directory.");
        if((File.GetAttributes(full)&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("Linked journal directory.");
        var paths=Directory.EnumerateFileSystemEntries(full).Take(MaxSegments+1).OrderBy(x=>x,StringComparer.Ordinal).ToArray();
        if(paths.Length>MaxSegments)throw new InvalidDataException("Too many journal entries.");
        long records=0,findings=0;long? first=null,last=null;
        long previousSegment=0;bool partial=false,started=false,stopped=false,gap=false;
        var rows=new Queue<Finding>();
        for(int index=0;index<paths.Length;index++)
        {
            token.ThrowIfCancellationRequested();
            var path=paths[index];var name=Path.GetFileName(path);
            if(name.Length!=27||!name.StartsWith("segment-",StringComparison.Ordinal)||!name.EndsWith(".ndjson",StringComparison.Ordinal)||
                !long.TryParse(name.AsSpan(8,12),NumberStyles.None,CultureInfo.InvariantCulture,out long segment)||segment<=0||
                (index>0&&segment!=previousSegment+1))
                throw new InvalidDataException("Invalid journal segment sequence.");
            if(index==0&&segment!=1)gap=true;
            previousSegment=segment;
            if((File.GetAttributes(path)&(FileAttributes.ReparsePoint|FileAttributes.Directory))!=0)
                throw new InvalidDataException("Invalid journal segment.");
            using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            if(stream.Length>MaxSegmentBytes)throw new InvalidDataException("Journal segment too large.");
            var bytes=new byte[(int)stream.Length];stream.ReadExactly(bytes);
            int offset=0;
            while(offset<bytes.Length)
            {
                token.ThrowIfCancellationRequested();
                int end=Array.IndexOf(bytes,(byte)10,offset);
                if(end<0)
                {
                    if(index!=paths.Length-1||bytes.Length-offset>=MaxRecordBytes)throw new InvalidDataException("Invalid journal tail.");
                    partial=true;break;
                }
                if(end-offset>=MaxRecordBytes)throw new InvalidDataException("Journal record too large.");
                using var doc=JsonDocument.Parse(bytes.AsMemory(offset,end-offset),new JsonDocumentOptions{MaxDepth=32});
                offset=end+1;
                var r=doc.RootElement;
                if(r.GetProperty("schemaVersion").GetInt32()!=1||r.GetProperty("mode").GetString()!="portable_foreground"||
                    r.GetProperty("sessionId").GetGuid()!=session||r.GetProperty("detectionValidation").GetString()!="not_assessed")
                    throw new InvalidDataException("Journal identity mismatch.");
                long sequence=r.GetProperty("sequence").GetInt64();
                if(sequence<=0||(last.HasValue&&(last.Value==long.MaxValue||sequence!=last.Value+1))||stopped)
                    throw new InvalidDataException("Journal record sequence mismatch.");
                if(first is null){first=sequence;if(sequence!=1)gap=true;}
                last=sequence;records++;
                string? type=r.GetProperty("eventType").GetString();
                var data=r.GetProperty("data");
                switch(type)
                {
                    case "started":
                        if(started||records!=1||sequence!=1)throw new InvalidDataException("Unexpected start.");
                        started=true;break;
                    case "health":
                        if(!started&&!gap)throw new InvalidDataException("Missing start.");
                        break;
                    case "finding":
                        if(!started&&!gap)throw new InvalidDataException("Missing start.");
                        string? id=data.GetProperty("ruleId").GetString(),method=data.GetProperty("method").GetString();
                        long packet=data.GetProperty("packetNumber").GetInt64();
                        DateTime timestamp=data.GetProperty("timestampUtc").GetDateTime();
                        if(id is null||!PortableReplayDispatcher.Supports(id)||method is not ("GET" or "POST")||
                            packet<=0||timestamp.Kind!=DateTimeKind.Utc)
                            throw new InvalidDataException("Invalid finding.");
                        findings++;if(rows.Count==limit)rows.Dequeue();
                        rows.Enqueue(new(sequence,packet,timestamp,id,method));break;
                    case "stopped":
                        // A startup failure may have only a stopped record.
                        if(data.GetProperty("status").GetString() is not ("failed" or "cancelled" or "stopped"))
                            throw new InvalidDataException("Invalid shutdown status.");
                        stopped=true;break;
                    default:throw new InvalidDataException("Unknown journal event.");
                }
            }
        }
        return new(session,partial?"incomplete_tail":stopped?"shutdown_recorded":"shutdown_not_recorded",
            gap,partial,records,findings,first,last,rows.ToArray());
    }
}
