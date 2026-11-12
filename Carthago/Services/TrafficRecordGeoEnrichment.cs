// SPDX-License-Identifier: MIT
using Carthago.Models;
using Carthago.Services.Geo;

namespace Carthago.Services;

internal static class TrafficRecordGeoEnrichment
{
    internal static void ApplySource(TrafficRecord record, GeoIpService.GeoInfo geo)
    {
        record.SrcCity ??= geo.CityName;
        record.SrcAsn ??= geo.Asn;
        record.SrcAsnOrganization ??= geo.AsnOrganization;
        record.SrcCountry ??= geo.CountryName;
        record.SrcCountryIso2 ??= geo.CountryIso2;
        record.SrcLat ??= geo.Latitude;
        record.SrcLon ??= geo.Longitude;
    }

    internal static void ApplyDestination(TrafficRecord record, GeoIpService.GeoInfo geo)
    {
        record.DstCity ??= geo.CityName;
        record.DstAsn ??= geo.Asn;
        record.DstAsnOrganization ??= geo.AsnOrganization;
        record.DstCountry ??= geo.CountryName;
        record.DstCountryIso2 ??= geo.CountryIso2;
        record.DstLat ??= geo.Latitude;
        record.DstLon ??= geo.Longitude;
    }
}
