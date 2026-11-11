// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Windows xUnit execution owner-deferred.
using Carthago.Views;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkInvestigationEvidenceHighlightTests
{
    [Fact]
    public void Traffic_Host_And_Dns_Question_Map_Only_To_Displayed_Typed_Metadata()
    {
        Assert.Equal(new[] { "Application · HTTP host", "Application · DNS query" },
            NetworkInvestigationPage.HighlightEvidenceKeys("traffic", new[] { "HTTP host", "DNS question" }));
    }

    [Fact]
    public void Exact_Address_And_Port_Map_To_Their_Recorded_Endpoint_Fields()
    {
        Assert.Equal(new[] { "Endpoints · source", "Endpoints · destination port" },
            NetworkInvestigationPage.HighlightEvidenceKeys("traffic", new[] { "Source IP (exact)", "Destination port (exact)" }));
    }

    [Fact]
    public void Event_Reference_Does_Not_Highlight_Case_Count_As_If_It_Were_The_Matching_Id()
    {
        Assert.Empty(NetworkInvestigationPage.HighlightEvidenceKeys("case", new[] { "Related event ID (exact reference)" }));
    }

    [Fact]
    public void Detection_Rule_And_Case_Title_Highlight_Are_Scoped_To_Their_Inspector()
    {
        Assert.Equal(new[] { "Rule · ID" },
            NetworkInvestigationPage.HighlightEvidenceKeys("detection", new[] { "Rule ID" }));
        Assert.Equal(new[] { "Case · title" },
            NetworkInvestigationPage.HighlightEvidenceKeys("case", new[] { "Case title" }));
        Assert.Empty(NetworkInvestigationPage.HighlightEvidenceKeys("traffic", new[] { "Rule ID" }));
    }
}
