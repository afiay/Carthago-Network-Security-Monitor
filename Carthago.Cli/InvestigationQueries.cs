// SPDX-License-Identifier: MIT
using Carthago.Contracts;
using Carthago.Services.SessionFiles;

namespace Carthago.Cli;

public static class InvestigationQueries
{
    public static bool IsId(string? value) => InvestigationProjection.IsId(value);
    public static string? NormalizeIp(string? value) => InvestigationProjection.NormalizeIp(value);
    public static string? NormalizeSeverity(string? value) => InvestigationProjection.NormalizeSeverity(value);

    public static async Task<InvestigationPage> ReadAsync(string path, InvestigationKind kind,
        InvestigationFilter filter, CancellationToken token)
    {
        InvestigationProjection.ValidateFilter(kind, filter);
        if (!string.Equals(Path.GetExtension(path), ".csa", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Expected CSA file.");
        var snapshot = await new CarthagoSessionArchiveService().OpenAsync(path, token);
        string category = kind switch { InvestigationKind.Alerts => "Alerts", InvestigationKind.Incidents => "Incidents",
            InvestigationKind.Events => "Traffic", InvestigationKind.Hosts => "Hosts", _ => throw new ArgumentException() };
        return InvestigationProjection.Select(snapshot.Categories[category], kind, filter, token);
    }
}
