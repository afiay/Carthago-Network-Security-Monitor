using Carthago.Engine.Rules;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class RuleTelemetryFieldContractTests
{
    [Theory]
    [InlineData("destination")]
    [InlineData("windows_protocol_context")]
    public void WinRm_Contract_Requires_Actual_Transport_And_Destination(string field)
    {
        var remoting = new TrafficRecord
        {
            Source = "10.0.0.70", Destination = "10.0.0.20", Protocol = "TCP",
            DestinationPort = 5985, ProcessName = "powershell.exe",
            Info = "Invoke-Command -EncodedCommand SQBFAFgA via WinRM"
        };
        Assert.True(RulePrecisionCatalog.HasField(field, remoting));
        Assert.False(RulePrecisionCatalog.HasField(field, new TrafficRecord { Info = "WinRM Invoke-Command" }));
    }

    [Theory]
    [InlineData("ot_asset_destination")]
    [InlineData("ics_protocol_function")]
    public void Bacnet_Write_Contract_Requires_Protocol_Behavior(string field)
    {
        var command = new TrafficRecord
        {
            Source = "10.20.0.44", Destination = "10.21.0.66", Protocol = "UDP",
            DestinationPort = 47808, ApplicationProtocol = "BACnet",
            Info = "BACnet confirmed WriteProperty request to analogOutput"
        };
        Assert.True(RulePrecisionCatalog.HasField(field, command));
        Assert.False(RulePrecisionCatalog.HasField(field, new TrafficRecord
        {
            Source = "10.20.0.44", Destination = "10.21.0.66", Protocol = "UDP", DestinationPort = 47808
        }));
    }

    [Theory]
    [InlineData("devops_or_secret_context")]
    [InlineData("kubernetes_or_container_context")]
    public void Service_Context_Fields_Require_Explicit_Api_Evidence(string field)
    {
        var positive = new TrafficRecord
        {
            Source = "10.0.0.2", Destination = "10.0.0.3", Protocol = "HTTP",
            HttpMethod = "POST", HttpHost = "jenkins.local",
            HttpUri = "/api/v1/namespaces/default/pods/web/exec"
        };
        Assert.True(RulePrecisionCatalog.HasField(field, positive));
        Assert.False(RulePrecisionCatalog.HasField(field, new TrafficRecord
        {
            Source = "10.0.0.2", Destination = "10.0.0.3", Protocol = "HTTP", HttpMethod = "GET", HttpUri = "/"
        }));
    }

    [Theory]
    [InlineData("database_destination")]
    [InlineData("database_protocol_or_query_marker")]
    public void Redis_Contract_Rejects_Port_Only_Without_Command_Evidence(string field)
    {
        var command = new TrafficRecord
        {
            Source = "10.0.0.65", Destination = "10.10.0.65", Protocol = "TCP",
            DestinationPort = 6379, ApplicationProtocol = "Redis", Info = "CONFIG SET dir /tmp"
        };
        Assert.True(RulePrecisionCatalog.HasField(field, command));
        Assert.False(RulePrecisionCatalog.HasField(field, new TrafficRecord
        {
            Source = "10.0.0.65", Destination = "10.10.0.65", Protocol = "TCP", DestinationPort = 6379
        }));
    }

    [Theory]
    [InlineData("external_destination_or_resolver")]
    [InlineData("tunnel_or_proxy_indicator")]
    public void Tunnel_Contract_Requires_Network_And_Proxy_Context(string field)
    {
        var tunnel = new TrafficRecord
        {
            Source = "10.0.0.68", Destination = "198.51.100.68", Protocol = "TCP",
            DestinationPort = 443, ProcessName = "cloudflared", Sni = "trycloudflare.com"
        };
        Assert.True(RulePrecisionCatalog.HasField(field, tunnel));
        Assert.False(RulePrecisionCatalog.HasField(field, new TrafficRecord { Source = "10.0.0.68", Protocol = "TCP" }));
    }

    [Theory]
    [InlineData("external_destination_or_upload_host")]
    [InlineData("file_or_payload_indicator")]
    public void Upload_Contract_Requires_Actual_Upload_Evidence(string field)
    {
        var upload = new TrafficRecord
        {
            Source = "10.0.0.67", Destination = "198.51.100.67", Protocol = "HTTP",
            DestinationPort = 443, HttpMethod = "POST", HttpHost = "storage.example.net",
            HttpUri = "/archive/upload", HttpUserAgent = "rclone/v1.66.0", ProcessName = "rclone.exe"
        };
        Assert.True(RulePrecisionCatalog.HasField(field, upload));
        Assert.False(RulePrecisionCatalog.HasField(field, new TrafficRecord
        {
            Source = "10.0.0.67", Destination = "198.51.100.67", Protocol = "TCP", DestinationPort = 443
        }));
    }
}
