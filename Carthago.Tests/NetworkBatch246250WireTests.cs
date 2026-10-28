// SPDX-License-Identifier: MIT
using System;
using System.Text;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;
public sealed class NetworkBatch246250WireTests
{
    private static byte[] SmbWrite()
    {
        var p = new byte[117];
        p[0] = 0; p[3] = 113;
        p[4] = 0xfe; p[5] = 0x53; p[6] = 0x4d; p[7] = 0x42;
        p[8] = 64; p[16] = 9; p[68] = 49;
        p[70] = 112; p[72] = 1;
        return p;
    }
    [Fact] public void Ftp_Stor_Request_Is_Classified() {
        Assert.True(NetworkBatch246250Wire.FtpUpload(Encoding.ASCII.GetBytes("STOR file.zip\r\n"),
            52000, 21, out var op));
        Assert.Equal("ftp.stor", op);
    }
    [Fact] public void Ftp_Appe_Request_Is_Classified() {
        Assert.True(NetworkBatch246250Wire.FtpUpload(Encoding.ASCII.GetBytes("APPE file.zip\r\n"),
            52000, 21, out var op));
        Assert.Equal("ftp.appe", op);
    }
    [Fact] public void Ftp_List_Is_Not_Upload() {
        Assert.False(NetworkBatch246250Wire.FtpUpload(Encoding.ASCII.GetBytes("LIST\r\n"),
            52000, 21, out _));
    }
    [Fact] public void Ftp_Reply_And_Wrong_Port_Are_Rejected() {
        Assert.False(NetworkBatch246250Wire.FtpUpload(Encoding.ASCII.GetBytes("STOR file.zip\r\n"),
            21, 52000, out _));
    }
    [Fact] public void Ftp_Malformed_Command_Is_Rejected() {
        Assert.False(NetworkBatch246250Wire.FtpUpload(Encoding.ASCII.GetBytes("STOR file.zip"),
            52000, 21, out _));
    }
    [Fact] public void Smb2_Write_Request_Is_Classified() {
        Assert.True(NetworkBatch246250Wire.Smb2Write(SmbWrite(), 52000, 445));
    }
    [Fact] public void Smb2_Create_Is_Not_Write() {
        var p = SmbWrite(); p[16] = 5;
        Assert.False(NetworkBatch246250Wire.Smb2Write(p, 52000, 445));
    }
    [Fact] public void Smb2_Server_Response_Is_Rejected() {
        var p = SmbWrite(); p[20] = 1;
        Assert.False(NetworkBatch246250Wire.Smb2Write(p, 52000, 445));
    }
    [Fact] public void Smb2_Bad_Frame_Length_Is_Rejected() {
        var p = SmbWrite(); p[3] = 100;
        Assert.False(NetworkBatch246250Wire.Smb2Write(p, 52000, 445));
    }
    [Fact] public void Smb2_Contradictory_Port_Is_Rejected() {
        Assert.False(NetworkBatch246250Wire.Smb2Write(SmbWrite(), 445, 52000));
    }
}
