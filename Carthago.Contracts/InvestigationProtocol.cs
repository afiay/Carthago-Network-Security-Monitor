// SPDX-License-Identifier: MIT
namespace Carthago.Contracts;

public sealed record InvestigationRequest(int Version, Guid Correlation, InvestigationKind Kind, InvestigationFilter Filter);
public sealed record InvestigationResponse(int Version, Guid Correlation, InvestigationKind Kind,
    LiveQueryState State, DateTimeOffset ObservedUtc, InvestigationPage? Page = null);

public static class InvestigationProtocol
{
    public const int Version = 3;
    public static void ValidateRequest(InvestigationRequest q)
    {
        if (q.Version != Version || q.Correlation == Guid.Empty || q.Filter is null)
            throw new InvalidDataException("Invalid investigation request.");
        try { InvestigationProjection.ValidateFilter(q.Kind, q.Filter); }
        catch (ArgumentException) { throw new InvalidDataException("Invalid investigation filter."); }
        if (q.Filter.Id is not null && (q.Filter.Offset != 0 || q.Filter.Limit != 1))
            throw new InvalidDataException("Invalid show filter.");
    }

    public static void ValidateResponse(InvestigationResponse r, InvestigationRequest q)
    {
        ValidateRequest(q);
        if (r.Version != Version || r.Correlation != q.Correlation || r.Kind != q.Kind ||
            r.ObservedUtc.Offset != TimeSpan.Zero || r.ObservedUtc == default ||
            r.State is not (LiveQueryState.Available or LiveQueryState.Unavailable))
            throw new InvalidDataException("Invalid investigation response.");
        if (r.State == LiveQueryState.Unavailable)
        {
            if (r.Page is not null) throw new InvalidDataException("Unavailable response contains data.");
            return;
        }
        var p = r.Page;
        if (p is null || p.Rows is null || p.Total < 0 || p.OmittedRows < 0 ||
            p.Offset != q.Filter.Offset || p.Limit != q.Filter.Limit ||
            p.Rows.Count != Math.Min(p.Limit, Math.Max(0, p.Total - p.Offset)) ||
            (q.Filter.Id is not null && p.Total > 1))
            throw new InvalidDataException("Invalid investigation page.");
        var ids = new HashSet<Guid>();
        foreach (var row in p.Rows)
        {
            if (row is null || (q.Kind != InvestigationKind.Hosts && !InvestigationProjection.IsId(row.Id)) ||
                (q.Kind == InvestigationKind.Hosts && (row.Id is not null || row.SourceIp is null)) ||
                (row.Id is not null && (!InvestigationProjection.IsId(row.Id) ||
                    !ids.Add(Guid.Parse(row.Id)))) ||
                (row.SourceIp is not null && InvestigationProjection.NormalizeIp(row.SourceIp) != row.SourceIp) ||
                (row.DestinationIp is not null && InvestigationProjection.NormalizeIp(row.DestinationIp) != row.DestinationIp) ||
                (row.Severity is not null && InvestigationProjection.NormalizeSeverity(row.Severity) != row.Severity) ||
                (row.RuleId is not null && !InvestigationProjection.IsRuleId(row.RuleId)) ||
                (row.Protocol is not null && !InvestigationProjection.IsProtocol(row.Protocol)) ||
                (row.Status is not null && !InvestigationProjection.IsStatus(q.Kind, row.Status)) ||
                (row.ObservedUtc is not null && row.ObservedUtc.Value.Offset != TimeSpan.Zero) ||
                row.SourcePort is < 0 or > 65535 || row.DestinationPort is < 0 or > 65535 ||
                row.RiskScore is < 0 || row.OccurrenceCount is < 0 || row.Length is < 0 ||
                (q.Filter.Id is not null && Guid.Parse(row.Id!) != Guid.Parse(q.Filter.Id)) ||
                (q.Filter.Severity is not null && row.Severity != InvestigationProjection.NormalizeSeverity(q.Filter.Severity)) ||
                (q.Filter.SourceIp is not null && row.SourceIp != InvestigationProjection.NormalizeIp(q.Filter.SourceIp)))
                throw new InvalidDataException("Invalid investigation row.");
        }
    }

    public static string Source(InvestigationKind kind) => kind switch
    {
        InvestigationKind.Alerts => "current_utc_day_detection_journal",
        InvestigationKind.Incidents => "recent_analytics_incident_cache",
        InvestigationKind.Events => "retained_traffic_window",
        InvestigationKind.Hosts => "observed_host_table",
        _ => throw new ArgumentException("Unknown source.")
    };
}
