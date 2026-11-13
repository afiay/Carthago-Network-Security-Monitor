// SPDX-License-Identifier: MIT
using System.Globalization;
using Carthago.Services;

namespace Carthago.Cli;

internal static class PcapInspectCommand
{
    internal sealed record Row(int PacketNumber,DateTime TimestampUtc,uint Nanoseconds,
        string? Source,string? Destination,int? SourcePort,int? DestinationPort,
        string? Protocol,string? ApplicationProtocol,int Length);
    internal sealed record Result(int LinkLayerType,string TimestampResolution,int PacketsRead,
        int Parsed,int Rejected,int CaptureTruncated,int ClockResets,int SampleLimit,IReadOnlyList<Row> Rows);

    internal static bool TryParse(string[] command,out string path,out int limit)
    {
        path="";limit=50;
        if(command.Length is not (3 or 5) || command[0]!="pcap" || command[1]!="inspect" ||
            string.IsNullOrWhiteSpace(command[2]) || command[2].StartsWith("--",StringComparison.Ordinal) ||
            !string.Equals(Path.GetExtension(command[2]),".pcap",StringComparison.OrdinalIgnoreCase))return false;
        path=command[2];
        return command.Length==3 || (command[3]=="--limit" &&
            int.TryParse(command[4],NumberStyles.None,CultureInfo.InvariantCulture,out limit) && limit is >=1 and <=100);
    }

    internal static async Task<Result> InspectAsync(string path,int limit,CancellationToken token)
    {
        if(limit is <1 or >100)throw new ArgumentOutOfRangeException(nameof(limit));
        await using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read,65536,
            FileOptions.Asynchronous|FileOptions.SequentialScan);
        if(stream.Length>PortablePcapReader.MaxFileBytes)throw new InvalidDataException("Capture exceeds limit.");
        var reader=await PortablePcapReader.OpenAsync(stream,token);
        var now=DateTime.UnixEpoch;
        DateTime? previous=null;
        uint previousNanos=0;
        var processor=new PortablePacketProcessor(()=>now);
        int read=0,parsed=0,rejected=0,truncated=0,resets=0;
        var rows=new List<Row>(limit);
        while(await reader.ReadAsync(token) is { } packet)
        {
            token.ThrowIfCancellationRequested();
            read++;
            now=packet.TimestampUtc;
            // Capture order is retained; never correlate across a backwards clock boundary.
            if(previous is DateTime last && (now<last || (now==last && packet.Nanoseconds<previousNanos)))
            { processor=new PortablePacketProcessor(()=>now);resets++; }
            previous=now;previousNanos=packet.Nanoseconds;
            if(packet.Data.Length<packet.OriginalLength){truncated++;continue;}
            // DLT_NULL stores the originating host's address-family byte order.
            // Core's existing NULL decoder expects little-endian family bytes.
            if(reader.LinkLayerType==0 && !reader.IsLittleEndian && packet.Data.Length>=4)
                Array.Reverse(packet.Data,0,4);
            var rec=processor.ParseFrame(packet.Data,reader.LinkLayerType);
            if(rec is null){rejected++;continue;}
            parsed++;
            if(rows.Count<limit)
                rows.Add(new Row(read,now,packet.Nanoseconds,rec.Source,rec.Destination,rec.SourcePort,
                    rec.DestinationPort,rec.Protocol,rec.ApplicationProtocol,rec.Length));
        }
        token.ThrowIfCancellationRequested();
        return new Result(reader.LinkLayerType,reader.TimestampResolution,read,parsed,rejected,truncated,resets,limit,rows);
    }
}
