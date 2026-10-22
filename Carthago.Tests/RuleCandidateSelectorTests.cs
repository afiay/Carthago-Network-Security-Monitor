using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Execution;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class RuleCandidateSelectorTests
{
    [Fact]
    public void CandidateSelector_Includes_Relevant_Dns_Rules()
    {
        var selector = new RuleCandidateSelector();
        var plan = selector.CreatePlan(RuleCatalog.Rules, CreateDnsRecord());

        Assert.Contains(plan.Entries, entry => entry.Rule.Descriptor.RuleId == "R094" && entry.ShouldEvaluate);
        Assert.Contains(plan.Entries, entry => entry.Rule.Descriptor.RuleId == "R102" && entry.ShouldEvaluate);
    }

    [Fact]
    public void CandidateSelector_Skips_Impossible_Http_Rules_For_DnsOnly_Traffic()
    {
        var selector = new RuleCandidateSelector();
        var plan = selector.CreatePlan(RuleCatalog.Rules, CreateDnsRecord());

        var httpRule = Assert.Single(plan.Entries.Where(entry => entry.Rule.Descriptor.RuleId == "R084"));
        Assert.False(httpRule.ShouldEvaluate);
        Assert.Contains("HTTP telemetry", httpRule.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CandidateSelector_Keeps_Health_And_Legacy_Rules()
    {
        var selector = new RuleCandidateSelector();
        var plan = selector.CreatePlan(RuleCatalog.Rules, CreateDnsRecord());

        Assert.Contains(plan.Entries, entry => entry.Rule.Descriptor.RuleId == "R050" && entry.ShouldEvaluate);
        Assert.Contains(plan.Entries, entry => entry.Rule.Descriptor.RuleId == "R001" && entry.ShouldEvaluate);
    }

    [Fact]
    public void Evaluation_Trace_Remains_Explainable_After_Selector_Runs()
    {
        RuleEngine.LoadConfig();
        _ = RuleEngine.Evaluate(CreateDnsRecord(), Sensitivity.Balanced);
        var trace = RuleEngine.LastEvaluationTrace;

        Assert.NotNull(trace);
        Assert.True(trace!.RulesSelectedCount < trace.RulesConsideredCount);
        Assert.Contains("R084", trace.SelectorSkippedRuleIds);
        Assert.Contains("R094", trace.SelectedRuleIds);
        Assert.Contains("R084", trace.SelectorReasonsByRuleId.Keys);
        Assert.Contains("HTTP telemetry", trace.SelectorReasonsByRuleId["R084"], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Performance_Trace_Records_Rules_Evaluated_Per_Packet()
    {
        RuleEngine.LoadConfig();
        _ = RuleEngine.Evaluate(CreateDnsRecord(), Sensitivity.Balanced);
        var trace = RuleEngine.LastEvaluationTrace;

        Assert.NotNull(trace);
        Assert.True(trace!.RulesConsideredCount > 0);
        Assert.True(trace.RulesSelectedCount > 0);
        Assert.True(trace.EvaluatedRuleIds.Count <= trace.RulesSelectedCount);
    }

    private static TrafficRecord CreateDnsRecord()
        => new()
        {
            Source = "10.0.0.10",
            Destination = "8.8.8.8",
            DestinationPort = 53,
            Protocol = "DNS",
            DnsQname = "cdn.example.com",
            DnsQtype = "A",
            DnsRcode = "NOERROR",
            IsUdp = true,
            Info = "Standard DNS query",
            ApplicationProtocol = "DNS",
            ApplicationService = "DNS"
        };
}
