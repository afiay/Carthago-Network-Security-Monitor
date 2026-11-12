// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Text;
using Carthago.Models;

namespace Carthago.Services.ProtocolIntelligence
{
    // One-shot TREE_CONNECT -> CREATE -> WRITE. Standalone plaintext disk
    // operations only. No pipelining, compound, DFS or CREATE contexts.
    // Raw names are transient; state retains categories and correlation IDs.
    internal sealed class Smb2WriteTargetContext
    {
        private int _stage;
        private ulong _message, _session, _persistent, _volatile;
        private uint _tree, _endSequence;
        private string? _shareKind, _fileKind;
        private Guid _createId;
        private DateTime _started;
        private static readonly UnicodeEncoding StrictUtf16 = new(false,false,true);

        internal static bool IsTreeRequest(ReadOnlySpan<byte> p)
            => Header(p,3,false) && U32(p,40)==0;

        // True retains state. Any unexpected payload, failed reply, timeout
        // or completed WRITE discards the entire chain.
        internal bool Observe(TrafficRecord record, ReadOnlySpan<byte> p, bool client,
            uint endSequence, uint ack, DateTime now)
        {
            if (now.Kind != DateTimeKind.Utc || record.Id == Guid.Empty) return false;
            if (_stage != 0 && (now < _started || now-_started > TimeSpan.FromSeconds(30))) return false;
            switch (_stage)
            {
                case 0:
                    if (!client || !IsTreeRequest(p) || p.Length < 78 || U16(p,68)!=9
                        || U16(p,70)!=0 || U16(p,72)!=72
                        || !TryText(p,76,U16(p,74),672,out var path)) return false;
                    if (!path.StartsWith("\\\\",StringComparison.Ordinal)) return false;
                    var parts=path.Substring(2).Split('\\');
                    if (parts.Length!=2 || parts[0].Length is <1 or >255
                        || parts[1].Length is <1 or >80 || parts[0].Contains('/') || parts[1].Contains('/')) return false;
                    string share=parts[1];
                    bool admin=share.Equals("ADMIN$",StringComparison.OrdinalIgnoreCase)
                        || (share.Length==2 && char.IsAsciiLetter(share[0]) && share[1]=='$');
                    _shareKind=admin?"administrative-disk":"other-disk";
                    _session=U64(p,44); _message=U64(p,28); _endSequence=endSequence; _started=now; _stage=1;
                    return true;
                case 1:
                    if (client || !Reply(p,3,ack) || p.Length!=84 || U16(p,68)!=16
                        || p[70]!=1 || p[71]!=0 || U32(p,40)==0
                        || (U32(p,72)&0x00008003u)!=0 || (U32(p,76)&8u)!=0) return false;
                    _tree=U32(p,40); _stage=2; return true;
                case 2:
                    if (!client || !Header(p,5,false) || U64(p,44)!=_session || U32(p,40)!=_tree
                        || p.Length<126 || U16(p,68)!=57 || U16(p,112)!=120
                        || U32(p,116)!=0 || U32(p,120)!=0
                        || !TryText(p,124,U16(p,114),1024,out var name)
                        || name.StartsWith("\\",StringComparison.Ordinal) || name.Contains('/')
                        || name.Contains(':') || InvalidComponents(name.Split('\\'))) return false;
                    if ((U32(p,108)&1u)!=0 || U32(p,104)>5) return false;
                    _fileKind=FileKind(name); _message=U64(p,28); _endSequence=endSequence;
                    _createId=record.Id; _stage=3; return true;
                case 3:
                    if (client || !Reply(p,5,ack) || U32(p,40)!=_tree
                        || p.Length!=156 || U16(p,68)!=89 || U32(p,148)!=0 || U32(p,152)!=0
                        || (U32(p,124)&0x10u)!=0) return false;
                    _persistent=U64(p,132); _volatile=U64(p,140);
                    if ((_persistent==0 && _volatile==0) || (_persistent==ulong.MaxValue && _volatile==ulong.MaxValue)) return false;
                    _stage=4; return true;
                case 4:
                    if (client && record.Smb2CompleteWriteRequestObserved && Header(p,9,false)
                        && p.Length>=117 && U64(p,44)==_session && U32(p,40)==_tree
                        && U64(p,84)==_persistent && U64(p,92)==_volatile)
                    {
                        record.Smb2WriteShareKind=_shareKind;
                        record.Smb2WriteFileKind=_fileKind;
                        record.Smb2WriteCreateCorrelationId=_createId;
                    }
                    return false;
                default: return false;
            }
        }

        private bool Reply(ReadOnlySpan<byte> p, ushort cmd, uint ack)
            => Header(p,cmd,true) && U32(p,12)==0 && U64(p,28)==_message
                && U64(p,44)==_session && unchecked((int)(ack-_endSequence))>=0;
        private static bool Header(ReadOnlySpan<byte> p, ushort cmd, bool response)
            => p.Length is >=68 and <=4096 && p[0]==0 && ((p[1]<<16)|(p[2]<<8)|p[3])==p.Length-4
                && p[4]==0xfe && p[5]==0x53 && p[6]==0x4d && p[7]==0x42
                && U16(p,8)==64 && U16(p,16)==cmd && U32(p,24)==0
                && (U32(p,20)&0x30000007u)==(response?1u:0u) && U64(p,44)!=0;
        private static bool TryText(ReadOnlySpan<byte> p,int offset,int length,int max,out string value)
        {
            value=string.Empty;
            if(length<2 || length>max || (length&1)!=0 || offset+length!=p.Length) return false;
            try { value=StrictUtf16.GetString(p.Slice(offset,length)); }
            catch(DecoderFallbackException) { return false; }
            foreach(char c in value) if(char.IsControl(c)) return false;
            return true;
        }
        private static string FileKind(string name)
        {
            int dot=name.LastIndexOf('.'), slash=name.LastIndexOf('\\');
            string ext=dot>slash?name.Substring(dot).ToLowerInvariant():string.Empty;
            return ext switch { ".exe" or ".dll" or ".sys" or ".msi" => "executable",
                ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" => "script", _ => "other" };
        }
        private static bool InvalidComponents(string[] parts)
        {
            foreach(var part in parts)
                if(part.Length==0 || part=="." || part==".." || part.EndsWith(" ",StringComparison.Ordinal)
                    || part.EndsWith(".",StringComparison.Ordinal)) return true;
            return false;
        }
        private static ushort U16(ReadOnlySpan<byte> s,int offset)=>BinaryPrimitives.ReadUInt16LittleEndian(s.Slice(offset,2));
        private static uint U32(ReadOnlySpan<byte> s,int offset)=>BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(offset,4));
        private static ulong U64(ReadOnlySpan<byte> s,int offset)=>BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(offset,8));
    }
}
