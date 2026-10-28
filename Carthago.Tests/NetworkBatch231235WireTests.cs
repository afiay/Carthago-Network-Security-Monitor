// SPDX-License-Identifier: MIT
using System.Text;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;
public sealed class NetworkBatch231235WireTests
{
    [Fact] public void Coap_Get_WellKnownCore_Option_Is_Recognized()
    {
        var bytes = new byte[] { 0x40, 0x01, 0x12, 0x34, 0xbb,
            (byte)'.', (byte)'w', (byte)'e', (byte)'l', (byte)'l', (byte)'-',
            (byte)'k', (byte)'n', (byte)'o', (byte)'w', (byte)'n',
            0x04, (byte)'c', (byte)'o', (byte)'r', (byte)'e' };
        Assert.True(NetworkBatch231235Wire.CoapDiscovery(bytes, 51000, 5683));
    }
    [Fact] public void Coap_Post_Is_Not_Discovery_Get()
    {
        var bytes = new byte[] { 0x40, 0x02, 0x12, 0x34, 0xbb,
            (byte)'.', (byte)'w', (byte)'e', (byte)'l', (byte)'l', (byte)'-',
            (byte)'k', (byte)'n', (byte)'o', (byte)'w', (byte)'n',
            0x04, (byte)'c', (byte)'o', (byte)'r', (byte)'e' };
        Assert.False(NetworkBatch231235Wire.CoapDiscovery(bytes, 51000, 5683));
    }
    [Fact] public void Rtsp_Play_Request_Line_Is_Recognized()
    {
        var bytes = Encoding.ASCII.GetBytes("PLAY rtsp://camera.local/live RTSP/1.0\r\nCSeq: 1\r\n\r\n");
        Assert.True(NetworkBatch231235Wire.RtspPlay(bytes, 51000, 554));
    }
    [Fact] public void Rtsp_Describe_Is_Not_Play()
    {
        var bytes = Encoding.ASCII.GetBytes("DESCRIBE rtsp://camera.local/live RTSP/1.0\r\nCSeq: 1\r\n\r\n");
        Assert.False(NetworkBatch231235Wire.RtspPlay(bytes, 51000, 554));
    }
    [Fact] public void Valid_WsDiscovery_Probe_Xml_Is_Recognized()
    {
        var xml = "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:d='http://schemas.xmlsoap.org/ws/2005/04/discovery'><s:Body><d:Probe /></s:Body></s:Envelope>";
        Assert.True(NetworkBatch231235Wire.WsDiscoveryProbe(Encoding.UTF8.GetBytes(xml), 51000, 3702));
    }
    [Fact] public void Xml_Dtd_Is_Not_Accepted_As_Probe()
    {
        var xml = "<!DOCTYPE x [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><d:Probe xmlns:d='http://schemas.xmlsoap.org/ws/2005/04/discovery'>&x;</d:Probe>";
        Assert.False(NetworkBatch231235Wire.WsDiscoveryProbe(Encoding.UTF8.GetBytes(xml), 51000, 3702));
    }
}
