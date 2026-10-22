using System;
using System.Collections.Generic;
using System.Net;
using Carthago.Services.Cisco;
using Lextm.SharpSnmpLib;
using Xunit;

namespace Carthago.Tests
{
    public sealed class SharpSnmpClientAdapterTests
    {
        [Fact]
        public void ConvertVariable_Preserves_Oid_And_Octet_Bytes()
        {
            var variable = new Variable(
                new ObjectIdentifier("1.3.6.1.4.1.9.9.23.1.2.1.1.5.10001.1"),
                new OctetString(new byte[] { 192, 0, 2, 24 }));

            var result = SharpSnmpClientAdapter.ConvertVariable(variable);

            Assert.Equal("1.3.6.1.4.1.9.9.23.1.2.1.1.5.10001.1", result.Oid);
            Assert.Equal(new byte[] { 192, 0, 2, 24 }, result.OctetStringBytes);
        }

        [Fact]
        public void ConvertVariable_Preserves_Text_Value()
        {
            var variable = new Variable(
                new ObjectIdentifier("1.3.6.1.4.1.9.9.23.1.2.1.1.6.10001.1"),
                new OctetString("dist-switch-01"));

            var result = SharpSnmpClientAdapter.ConvertVariable(variable);

            Assert.Equal("dist-switch-01", result.ValueText);
        }

        [Fact]
        public void ConvertVariable_Leaves_Bytes_Null_For_Non_Octet_Data()
        {
            var variable = new Variable(
                new ObjectIdentifier("1.3.6.1.2.1.1.7.0"),
                new Integer32(42));

            var result = SharpSnmpClientAdapter.ConvertVariable(variable);

            Assert.Equal("42", result.ValueText);
            Assert.Null(result.OctetStringBytes);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(65536)]
        public void Walk_Rejects_Invalid_Port(int port)
        {
            var adapter = new SharpSnmpClientAdapter();

            var error = Assert.Throws<ArgumentOutOfRangeException>(() => adapter.Walk(
                "192.0.2.1",
                port,
                "public",
                "1.3.6.1.2.1"));

            Assert.Equal("port", error.ParamName);
        }

        [Theory]
        [InlineData(0, 1, 25, "timeoutMilliseconds")]
        [InlineData(3000, -1, 25, "retries")]
        [InlineData(3000, 1, 0, "maxRepetitions")]
        public void Walk_Rejects_Invalid_Request_Settings(
            int timeoutMilliseconds,
            int retries,
            int maxRepetitions,
            string expectedParameter)
        {
            var adapter = new SharpSnmpClientAdapter();

            var error = Assert.Throws<ArgumentOutOfRangeException>(() => adapter.Walk(
                "192.0.2.1",
                161,
                "public",
                "1.3.6.1.2.1",
                timeoutMilliseconds,
                retries,
                maxRepetitions));

            Assert.Equal(expectedParameter, error.ParamName);
        }

        [Fact]
        public void Walk_Retries_Each_Page_Without_Discarding_Earlier_Pages()
        {
            const string root = "1.3.6.1.2.1";
            var client = new ScriptedBulkRequestClient(
                SnmpBulkRequestResult.TimedOut(new TimeoutException("first page")),
                SnmpBulkRequestResult.Success(Variable(root + ".1", "first")),
                SnmpBulkRequestResult.TimedOut(new TimeoutException("second page")),
                SnmpBulkRequestResult.Success(Variable(root + ".2", "second")),
                SnmpBulkRequestResult.Success(Variable("1.3.6.1.3.1", "outside")));
            var adapter = new SharpSnmpClientAdapter(client);

            var result = adapter.Walk("192.0.2.1", 161, "public", root, retries: 1);

            Assert.Collection(
                result,
                item => Assert.Equal(root + ".1", item.Oid),
                item => Assert.Equal(root + ".2", item.Oid));
            Assert.Equal(
                new[] { root, root, root + ".1", root + ".1", root + ".2" },
                client.Seeds);
        }

        [Fact]
        public void Walk_Returns_Accumulated_Results_When_Agent_Reports_Error()
        {
            const string root = "1.3.6.1.2.1";
            var client = new ScriptedBulkRequestClient(
                SnmpBulkRequestResult.Success(Variable(root + ".1", "first")),
                SnmpBulkRequestResult.Error());
            var adapter = new SharpSnmpClientAdapter(client);

            var result = adapter.Walk("192.0.2.1", 161, "public", root);

            var item = Assert.Single(result);
            Assert.Equal(root + ".1", item.Oid);
            Assert.Equal("first", item.ValueText);
        }

        [Fact]
        public void Walk_Rethrows_Timeout_After_Per_Page_Retries_Are_Exhausted()
        {
            var terminalTimeout = new TimeoutException("terminal");
            var client = new ScriptedBulkRequestClient(
                SnmpBulkRequestResult.TimedOut(new TimeoutException("initial")),
                SnmpBulkRequestResult.TimedOut(terminalTimeout));
            var adapter = new SharpSnmpClientAdapter(client);

            var error = Assert.Throws<TimeoutException>(() => adapter.Walk(
                "192.0.2.1",
                161,
                "public",
                "1.3.6.1.2.1",
                retries: 1));

            Assert.Same(terminalTimeout, error);
        }

        private static Variable Variable(string oid, string value)
            => new(new ObjectIdentifier(oid), new OctetString(value));

        private sealed class ScriptedBulkRequestClient : ISnmpBulkRequestClient
        {
            private readonly Queue<SnmpBulkRequestResult> _results;

            public ScriptedBulkRequestClient(params SnmpBulkRequestResult[] results)
                => _results = new Queue<SnmpBulkRequestResult>(results);

            public List<string> Seeds { get; } = new();

            public SnmpBulkRequestResult GetNextPage(
                IPEndPoint endpoint,
                OctetString community,
                ObjectIdentifier seed,
                int timeoutMilliseconds,
                int maxRepetitions)
            {
                Seeds.Add(seed.ToString());
                return _results.Dequeue();
            }
        }
    }
}
