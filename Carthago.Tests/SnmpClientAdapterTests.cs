using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Services.Cisco;
using Xunit;

namespace Carthago.Tests
{
    public sealed class SnmpClientAdapterTests
    {
        [Fact]
        public async Task Discovery_Uses_Adapter_And_Parses_Cdp_Neighbors()
        {
            var adapter = new FakeSnmpClientAdapter();
            var service = new CiscoDiscoveryService(adapter);

            var neighbors = await service.DiscoverNeighborsAsync(
                new CiscoDevice { Host = "192.0.2.10", Name = "core-switch" },
                "public");

            Assert.Single(neighbors);
            var neighbor = neighbors[0];
            Assert.Equal("dist-switch-01", neighbor.RemoteDeviceId);
            Assert.Equal("GigabitEthernet1/0/24", neighbor.RemoteInterface);
            Assert.Equal("WS-C3850", neighbor.RemotePlatform);
            Assert.Equal("192.0.2.24", neighbor.RemoteMgmtAddress);
        }

        private sealed class FakeSnmpClientAdapter : ISnmpClientAdapter
        {
            public IReadOnlyList<SnmpWalkVariable> Walk(string host, int port, string community, string rootOid, int timeoutMilliseconds = 3000, int retries = 1, int maxRepetitions = 25)
                => new[]
                {
                    new SnmpWalkVariable(rootOid + ".6.10001.1", "dist-switch-01"),
                    new SnmpWalkVariable(rootOid + ".7.10001.1", "GigabitEthernet1/0/24"),
                    new SnmpWalkVariable(rootOid + ".8.10001.1", "WS-C3850"),
                    new SnmpWalkVariable(rootOid + ".9.10001.1", "Switch, IGMP"),
                    new SnmpWalkVariable(rootOid + ".5.10001.1", "192.0.2.24", new byte[] { 192, 0, 2, 24 })
                };
        }
    }
}
