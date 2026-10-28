// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Text;
using System.Xml;

namespace Carthago.Services
{
    // Strict bounded first-packet recognition; no TCP reassembly, TLS
    // decryption, authorization or action-success inference.
    internal static class NetworkBatch231235Wire
    {
        internal static bool CoapDiscovery(ReadOnlySpan<byte> bytes, int? src, int? dst)
        {
            if (dst != 5683 || bytes.Length < 5 || bytes.Length > 1024
                || (bytes[0] >> 6) != 1 || bytes[1] != 1) return false;
            int tokenLength = bytes[0] & 15;
            if (tokenLength > 8 || 4 + tokenLength > bytes.Length) return false;
            int pos = 4 + tokenLength, option = 0;
            var path = new StringBuilder();
            while (pos < bytes.Length)
            {
                byte header = bytes[pos++];
                if (header == 0xff) break;
                int delta = header >> 4, size = header & 15;
                if (delta == 15 || size == 15) return false;
                if (delta == 13) { if (pos >= bytes.Length) return false; delta = 13 + bytes[pos++]; }
                else if (delta == 14) { if (pos + 2 > bytes.Length) return false; delta = 269 + (bytes[pos++] << 8 | bytes[pos++]); }
                if (size == 13) { if (pos >= bytes.Length) return false; size = 13 + bytes[pos++]; }
                else if (size == 14) { if (pos + 2 > bytes.Length) return false; size = 269 + (bytes[pos++] << 8 | bytes[pos++]); }
                option += delta;
                if (pos + size > bytes.Length) return false;
                if (option == 11)
                {
                    if (path.Length > 0) path.Append('/');
                    path.Append(Encoding.UTF8.GetString(bytes.Slice(pos, size)));
                }
                pos += size;
            }
            return path.ToString() == ".well-known/core";
        }

        internal static bool RtspPlay(ReadOnlySpan<byte> bytes, int? src, int? dst)
        {
            if (dst is not (554 or 8554) || bytes.Length is < 20 or > 4096) return false;
            var text = Encoding.ASCII.GetString(bytes.Slice(0, Math.Min(bytes.Length, 512)));
            int end = text.IndexOf("\r\n", StringComparison.Ordinal);
            if (end < 0) return false;
            var line = text[..end].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return line.Length == 3 && line[0] == "PLAY" && line[2] == "RTSP/1.0"
                && Uri.TryCreate(line[1], UriKind.Absolute, out var uri)
                && uri.Scheme.Equals("rtsp", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(uri.Host);
        }

        internal static bool WsDiscoveryProbe(ReadOnlySpan<byte> bytes, int? src, int? dst)
        {
            if (dst != 3702 || bytes.Length is < 40 or > 4096) return false;
            try
            {
                var settings = new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = 4096,
                    IgnoreComments = true
                };
                using var reader = XmlReader.Create(new StringReader(Encoding.UTF8.GetString(bytes)), settings);
                bool probe = false, onvifVideoType = false;
                while (reader.Read())
                {
                    if (reader.NodeType != XmlNodeType.Element) continue;
                    var discovery = reader.NamespaceURI == "http://schemas.xmlsoap.org/ws/2005/04/discovery"
                        || reader.NamespaceURI == "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01";
                    if (!discovery) continue;
                    if (reader.LocalName == "Probe") probe = true;
                    if (reader.LocalName == "Types")
                    {
                        var types = reader.ReadElementContentAsString();
                        foreach (var name in types.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
                            if (name.EndsWith(":NetworkVideoTransmitter", StringComparison.Ordinal)
                                || name == "NetworkVideoTransmitter")
                                onvifVideoType = true;
                    }
                }
                return probe && onvifVideoType
                    && Encoding.UTF8.GetString(bytes).Contains(
                        "http://www.onvif.org/ver10/network/wsdl", StringComparison.Ordinal);
            }
            catch (XmlException) { }
            return false;
        }
    }
}
