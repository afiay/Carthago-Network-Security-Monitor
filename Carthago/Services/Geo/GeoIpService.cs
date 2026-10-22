// SPDX-License-Identifier: MIT
// File: Services/Geo/GeoIpService.cs
using System;
using System.IO;
using System.Net;
using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Responses;

namespace Carthago.Services.Geo
{
    public sealed class GeoIpService : IDisposable
    {
        private readonly string _baseDir = AppContext.BaseDirectory;
        private DatabaseReader? _cityDb;
        private DatabaseReader? _asnDb;

        public bool IsCityDbAvailable { get; private set; }
        public bool IsAsnDbAvailable { get; private set; }

        public string CityDbPath => Path.Combine(_baseDir, "Data", "GeoLite2-City.mmdb");
        public string AsnDbPath => Path.Combine(_baseDir, "Data", "GeoLite2-ASN.mmdb");

        public GeoIpService()
        {
            try
            {
                if (File.Exists(CityDbPath)) { _cityDb = new DatabaseReader(CityDbPath); IsCityDbAvailable = true; }
            }
            catch { IsCityDbAvailable = false; }

            try
            {
                if (File.Exists(AsnDbPath)) { _asnDb = new DatabaseReader(AsnDbPath); IsAsnDbAvailable = true; }
            }
            catch { IsAsnDbAvailable = false; }
        }

        public GeoInfo? Lookup(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip) || !IPAddress.TryParse(ip, out var addr)) return null;

            string? country = null, iso2 = null, city = null, asnOrg = null;
            long? asn = null;
            double? lat = null, lon = null;

            if (IsCityDbAvailable && _cityDb != null)
            {
                try
                {
                    CityResponse res = _cityDb.City(addr);
                    country = res.Country?.Name;
                    iso2 = res.Country?.IsoCode;
                    city = res.City?.Name;
                    lat = res.Location?.Latitude;
                    lon = res.Location?.Longitude;
                }
                catch { /* not found */ }
            }

            if (IsAsnDbAvailable && _asnDb != null)
            {
                try
                {
                    var res = _asnDb.Asn(addr);
                    asn = res.AutonomousSystemNumber;
                    asnOrg = res.AutonomousSystemOrganization;
                }
                catch { /* ignore */ }
            }

            if (lat is null || lon is null) return null;

            return new GeoInfo
            {
                CountryName = country,
                CountryIso2 = iso2,
                CityName = city,
                Latitude = lat.Value,
                Longitude = lon.Value,
                Asn = asn,
                AsnOrganization = asnOrg
            };
        }

        public bool TryLookup(string ip, out GeoInfo info)
        {
            info = Lookup(ip) ?? default!;
            return (info is not null);
        }

        public void Dispose()
        {
            _cityDb?.Dispose();
            _asnDb?.Dispose();
        }

        public sealed class GeoInfo
        {
            public string? CountryName { get; init; }
            public string? CountryIso2 { get; init; }
            public string? CityName { get; init; }
            public double Latitude { get; init; }
            public double Longitude { get; init; }
            public long? Asn { get; init; }
            public string? AsnOrganization { get; init; }
        }
    }
}
