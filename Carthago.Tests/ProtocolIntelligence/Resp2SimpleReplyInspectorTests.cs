// SPDX-License-Identifier: MIT
// GA R437 — SOURCE CANDIDATE — UNVERIFIED. Hand-authored wire replies only.
using System;
using System.Text;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence;

public sealed class Resp2SimpleReplyInspectorTests
{
    [Fact]
    public void Exact_Ok_Is_The_Only_Positive_Simple_Status()
    {
        Assert.True(Resp2SimpleReplyInspector.TryInspect("+OK\r\n"u8, out var accepted));
        Assert.Equal(Resp2SimpleReplyKind.Ok, accepted);

        foreach (var bytes in new[]
        {
            "+PONG\r\n", "+OKAY\r\n", "+OK\r\n+OK\r\n",
            " +OK\r\n", ":1\r\n", "$2\r\nOK\r\n", "+ok\r\n"
        })
        {
            Assert.False(Resp2SimpleReplyInspector.TryInspect(
                Encoding.ASCII.GetBytes(bytes), out var unknown));
            Assert.Equal(Resp2SimpleReplyKind.Unknown, unknown);
        }
    }

    [Theory]
    [InlineData("-ERR unknown command\r\n")]
    [InlineData("-NOPERM no permissions\r\n")]
    [InlineData("-WRONGTYPE incorrect value type\r\n")]
    public void Complete_Error_Reply_Is_Rejection_Not_Ok(string reply)
    {
        Assert.True(Resp2SimpleReplyInspector.TryInspect(
            Encoding.ASCII.GetBytes(reply), out var observed));
        Assert.Equal(Resp2SimpleReplyKind.Error, observed);
    }

    [Fact]
    public void Truncated_Embedded_Line_And_Control_Bytes_Fail_Closed()
    {
        foreach (var reply in new[]
        {
            "+OK\r", "-ERR incomplete",
            "-ERR embedded\r\n+OK\r\n", "-ERR bad\rtext\r\n",
            "-ERR \tsecret\r\n", "-\r\n"
        })
            Assert.False(Resp2SimpleReplyInspector.TryInspect(
                Encoding.ASCII.GetBytes(reply), out _));
    }

    [Fact]
    public void Response_Classifier_Bounds_Input_Without_Retaining_Private_Text()
    {
        var privateError = "-ERR password-was-not-accepted\r\n";
        Assert.True(Resp2SimpleReplyInspector.TryInspect(
            Encoding.ASCII.GetBytes(privateError), out var classified));
        Assert.Equal(Resp2SimpleReplyKind.Error, classified);
        Assert.DoesNotContain("password", classified.ToString());
        Assert.False(Resp2SimpleReplyInspector.TryInspect(
            Encoding.ASCII.GetBytes("-ERR " + new string('x', 256) + "\r\n"), out _));
        Assert.False(Resp2SimpleReplyInspector.TryInspect(
            Array.Empty<byte>(), out _));
    }
}
