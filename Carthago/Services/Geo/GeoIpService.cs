// SPDX-License-Identifier: MIT
// File: Services/Geo/GeoIpService.cs
using System;
using System.IO;
using System.Collections.Generic;
using System.Net;
using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Responses;
using MaxMind.GeoIP2.Exceptions;

namespace Carthago.Services.Geo
{
    public sealed class GeoIpService : IDisposable
    {
        private readonly string _baseDir;
        private DatabaseReader? _cityDb;
        private DatabaseReader? _asnDb;
        private readonly object _lookupGate = new();
        private readonly Dictionary<IPAddress, (GeoInfo? Info, long Expires)> _cache = new();
        private readonly int _cacheCapacity;
        private readonly Func<long> _clock;
        private const long CacheTtlMs = 300_000;
        private long _positiveHits, _negativeHits, _misses, _expired, _evicted;
        public readonly record struct CacheHealthSnapshot(long PositiveHits, long NegativeHits, long Misses,
            long Expired, long Evicted, int Occupancy, int Capacity)
        {
            public long Requests => PositiveHits + NegativeHits + Misses;
        }
        public CacheHealthSnapshot CacheHealth
        {
            get { lock (_lookupGate) return new(_positiveHits, _negativeHits, _misses, _expired, _evicted, _cache.Count, _cacheCapacity); }
        }

        public enum DatabaseAvailability { Missing, Unavailable, Ready }

        public DatabaseAvailability CityDatabaseStatus { get; private set; }
        public DatabaseAvailability AsnDatabaseStatus { get; private set; }
        public bool IsCityDbAvailable => CityDatabaseStatus == DatabaseAvailability.Ready;
        public bool IsAsnDbAvailable => AsnDatabaseStatus == DatabaseAvailability.Ready;

        public string CityDbPath => Path.Combine(_baseDir, "Data", "GeoLite2-City.mmdb");
        public string AsnDbPath => Path.Combine(_baseDir, "Data", "GeoLite2-ASN.mmdb");

        public GeoIpService() : this(AppContext.BaseDirectory) { }

        internal GeoIpService(string baseDir, int cacheCapacity = 4096, Func<long>? clock = null)
        {
            if (cacheCapacity <= 0) throw new ArgumentOutOfRangeException(nameof(cacheCapacity));
            _cacheCapacity = cacheCapacity;
            _clock = clock ?? (() => Environment.TickCount64);
            _baseDir = baseDir;
            _cityDb = OpenDatabase(CityDbPath, true, out var cityStatus);
            CityDatabaseStatus = cityStatus;
            _asnDb = OpenDatabase(AsnDbPath, false, out var asnStatus);
            AsnDatabaseStatus = asnStatus;
        }

        private static DatabaseReader? OpenDatabase(string path, bool city, out DatabaseAvailability status)
        {
            try
            {
                var reader = new DatabaseReader(path);
                if (!IsExpectedDatabaseType(reader.Metadata.DatabaseType, city))
                {
                    reader.Dispose();
                    status = DatabaseAvailability.Unavailable;
                    return null;
                }
                status = DatabaseAvailability.Ready;
                return reader;
            }
            catch (FileNotFoundException) { status = DatabaseAvailability.Missing; }
            catch (DirectoryNotFoundException) { status = DatabaseAvailability.Missing; }
            catch { status = DatabaseAvailability.Unavailable; }
            return null;
        }

        // Validate the actual metadata, not the filename. Only supported City/ASN editions.
        internal static bool IsExpectedDatabaseType(string? type, bool city) =>
            city
                ? type is "GeoLite2-City" or "GeoIP2-City"
                : type is "GeoLite2-ASN" or "GeoIP2-ASN";

        public enum LookupOutcome { NotAttempted, Found, NotFound, Failed }

        // Service-lifetime completed database attempts; skipped requests are excluded.
        public readonly record struct LookupHealthSnapshot(long Found, long NotFound, long Failed)
        {
            public long Attempts => Found + NotFound + Failed;
        }

        internal sealed class LookupHealthCounter
        {
            private readonly object _gate = new();
            private long _found, _notFound, _failed;

            internal void Record(LookupOutcome outcome)
            {
                if (outcome == LookupOutcome.NotAttempted) return;
                lock (_gate)
                {
                    switch (outcome)
                    {
                        case LookupOutcome.Found: _found++; break;
                        case LookupOutcome.NotFound: _notFound++; break;
                        case LookupOutcome.Failed: _failed++; break;
                    }
                }
            }

            internal LookupHealthSnapshot Snapshot()
            {
                lock (_gate) return new(_found, _notFound, _failed);
            }
        }

        private readonly LookupHealthCounter _cityHealth = new();
        private readonly LookupHealthCounter _asnHealth = new();
        public LookupHealthSnapshot CityLookupHealth => _cityHealth.Snapshot();
        public LookupHealthSnapshot AsnLookupHealth => _asnHealth.Snapshot();

        public GeoInfo? Lookup(string ip)
        {
            if (!TryGetLookupAddress(ip, out var address)) return null;
            lock (_lookupGate)
            {
                if (!IsCityDbAvailable && !IsAsnDbAvailable) return null;
                var now = _clock();
                if (_cache.TryGetValue(address, out var cached))
                {
                    if (now < cached.Expires)
                    {
                        if (cached.Info is null) _negativeHits++; else _positiveHits++;
                        return cached.Info;
                    }
                    _expired++;
                    _cache.Remove(address);
                }
                _misses++;
                var result = LookupUncached(ip);
                // Cache completed hits/misses, never failures or wholly skipped requests.
                if (result.City != LookupOutcome.Failed && result.Asn != LookupOutcome.Failed
                    && (result.City != LookupOutcome.NotAttempted || result.Asn != LookupOutcome.NotAttempted))
                {
                    if (_cache.Count >= _cacheCapacity)
                    {
                        _evicted += _cache.Count;
                        _cache.Clear();
                    }
                    _cache[address] = (result.Info, now + CacheTtlMs);
                }
                return result.Info;
            }
        }

        internal (GeoInfo? Info, LookupOutcome City, LookupOutcome Asn) LookupWithOutcomes(string ip)
        {
            lock (_lookupGate) return LookupUncached(ip);
        }

        private (GeoInfo? Info, LookupOutcome City, LookupOutcome Asn) LookupUncached(string ip)
        {
            if (!TryGetLookupAddress(ip, out var addr)) return (null, LookupOutcome.NotAttempted, LookupOutcome.NotAttempted);
            var cityOutcome = LookupOutcome.NotAttempted;
            var asnOutcome = LookupOutcome.NotAttempted;

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
                    cityOutcome = LookupOutcome.Found;
                }
                catch (AddressNotFoundException) { cityOutcome = LookupOutcome.NotFound; }
                catch { cityOutcome = LookupOutcome.Failed; }
            }

            if (IsAsnDbAvailable && _asnDb != null)
            {
                try
                {
                    var res = _asnDb.Asn(addr);
                    asn = res.AutonomousSystemNumber;
                    asnOrg = res.AutonomousSystemOrganization;
                    asnOutcome = LookupOutcome.Found;
                }
                catch (AddressNotFoundException) { asnOutcome = LookupOutcome.NotFound; }
                catch { asnOutcome = LookupOutcome.Failed; }
            }

            _cityHealth.Record(cityOutcome);
            _asnHealth.Record(asnOutcome);
            return (CreateResult(country, iso2, city, lat, lon, asn, asnOrg), cityOutcome, asnOutcome);
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
            lock (_lookupGate)
            {
            _cache.Clear();
            _cityDb?.Dispose();
            _cityDb = null;
            _asnDb?.Dispose();
            _asnDb = null;
            if (CityDatabaseStatus == DatabaseAvailability.Ready)
                CityDatabaseStatus = DatabaseAvailability.Unavailable;
            if (AsnDatabaseStatus == DatabaseAvailability.Ready)
                AsnDatabaseStatus = DatabaseAvailability.Unavailable;
            }
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
