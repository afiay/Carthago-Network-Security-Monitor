// SPDX-License-Identifier: MIT
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;
public sealed class NetworkBatch226230WireTests
{
    [Fact] public void Cip_ListIdentity_Encapsulation_Is_Recognized()
    {
        var bytes = new byte[24]; bytes[0] = 0x63;
        Assert.True(NetworkBatch226230Wire.CipListIdentity(bytes, 51000, 44818));
    }
    [Fact] public void Cip_Port_Without_ListIdentity_Command_Is_Rejected()
    {
        var bytes = new byte[24]; bytes[0] = 0x65;
        Assert.False(NetworkBatch226230Wire.CipListIdentity(bytes, 51000, 44818));
    }
    [Fact] public void Cip_Nonzero_Declared_Length_Is_Rejected()
    {
        var bytes = new byte[24]; bytes[0] = 0x63; bytes[2] = 1;
        Assert.False(NetworkBatch226230Wire.CipListIdentity(bytes, 51000, 44818));
    }
    [Fact] public void Retained_Publish_Parses_Topic_Without_Payload()
    {
        byte[] bytes = { 0x31, 0x0a, 0x00, 0x07, (byte)'d', (byte)'e', (byte)'v',
            (byte)'/', (byte)'c', (byte)'m', (byte)'d', 0x01 };
        Assert.True(NetworkBatch226230Wire.Mqtt(bytes, 51000, 1883, out var operation, out var topic, out var retain));
        Assert.Equal("mqtt.publish", operation); Assert.Equal("dev/cmd", topic); Assert.True(retain);
    }
    [Fact] public void Mqtt_Declared_Length_Mismatch_Is_Rejected()
    {
        byte[] bytes = { 0x31, 0x0b, 0x00, 0x07, (byte)'d', (byte)'e', (byte)'v',
            (byte)'/', (byte)'c', (byte)'m', (byte)'d', 0x01 };
        Assert.False(NetworkBatch226230Wire.Mqtt(bytes, 51000, 1883, out _, out _, out _));
    }
    [Fact] public void NonRetained_Publish_Is_Parsed_But_Not_Labeled_Retained()
    {
        byte[] bytes = { 0x30, 0x09, 0x00, 0x07, (byte)'d', (byte)'e', (byte)'v',
            (byte)'/', (byte)'c', (byte)'m', (byte)'d' };
        Assert.True(NetworkBatch226230Wire.Mqtt(bytes, 51000, 1883, out _, out _, out var retain));
        Assert.False(retain);
    }
    [Fact] public void Encrypted_Port_Is_Not_Parsed_As_Cleartext_Mqtt()
    {
        byte[] bytes = { 0x30, 0x09, 0x00, 0x07, (byte)'d', (byte)'e', (byte)'v',
            (byte)'/', (byte)'c', (byte)'m', (byte)'d' };
        Assert.False(NetworkBatch226230Wire.Mqtt(bytes, 51000, 8883, out _, out _, out _));
    }
}
