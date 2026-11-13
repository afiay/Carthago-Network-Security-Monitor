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
        private readonly string _baseDir;
        private DatabaseReader? _cityDb;
        private DatabaseReader? _asnDb;

        public enum DatabaseAvailability { Missing, Unavailable, Ready }

        public DatabaseAvailability CityDatabaseStatus { get; private set; }
        public DatabaseAvailability AsnDatabaseStatus { get; private set; }
        public bool IsCityDbAvailable => CityDatabaseStatus == DatabaseAvailability.Ready;
        public bool IsAsnDbAvailable => AsnDatabaseStatus == DatabaseAvailability.Ready;

        public string CityDbPath => Path.Combine(_baseDir, "Data", "GeoLite2-City.mmdb");
        public string AsnDbPath => Path.Combine(_baseDir, "Data", "GeoLite2-ASN.mmdb");

        public GeoIpService() : this(AppContext.BaseDirectory) { }

        internal GeoIpService(string baseDir)
        {
            _baseDir = baseDir;
            _cityDb = OpenDatabase(CityDbPath, out var cityStatus);
            CityDatabaseStatus = cityStatus;
            _asnDb = OpenDatabase(AsnDbPath, out var asnStatus);
            AsnDatabaseStatus = asnStatus;
        }

        private static DatabaseReader? OpenDatabase(string path, out DatabaseAvailability status)
        {
            try
            {
                var reader = new DatabaseReader(path);
                status = DatabaseAvailability.Ready;
                return reader;
            }
            catch (FileNotFoundException) { status = DatabaseAvailability.Missing; }
            catch (DirectoryNotFoundException) { status = DatabaseAvailability.Missing; }
            catch { status = DatabaseAvailability.Unavailable; }
            return null;
        }

        public GeoInfo? Lookup(string ip)
        {
            if (!TryGetLookupAddress(ip, out var addr)) return null;

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

            return CreateResult(country, iso2, city, lat, lon, asn, asnOrg);
        }

        // Keep the provider boundary consistent with capture endpoint scope.
        // Mapped IPv4 must query the IPv4 database key, not the IPv6 wrapper.
        internal static bool TryGetLookupAddress(string? ip, out IPAddress address)
        {
            address = IPAddress.None;
            if (!IPAddress.TryParse(ip, out var parsed)
                || EndpointIpEnrichment.Classify(ip) != "Public")
                return false;
            address = EndpointIpEnrichment.Normalize(parsed);
            return true;
        }

        // Coordinates are optional; ASN-only and country-only results are useful.
        internal static GeoInfo? CreateResult(string? country, string? iso2, string? city,
            double? lat, double? lon, long? asn, string? asnOrg)
        {
            if (lat is not double latitude || lon is not double longitude
                || !double.IsFinite(latitude) || !double.IsFinite(longitude)
                || latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180)
            {
                lat = null;
                lon = null;
            }
            if (lat is null && asn is null && string.IsNullOrWhiteSpace(asnOrg)
                && string.IsNullOrWhiteSpace(country) && string.IsNullOrWhiteSpace(iso2)
                && string.IsNullOrWhiteSpace(city)) return null;

            return new GeoInfo
            {
                CountryName = country,
                CountryIso2 = iso2,
                CityName = city,
                Latitude = lat,
                Longitude = lon,
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
            public double? Latitude { get; init; }
            public double? Longitude { get; init; }
            public long? Asn { get; init; }
            public string? AsnOrganization { get; init; }
        }
    }
}
