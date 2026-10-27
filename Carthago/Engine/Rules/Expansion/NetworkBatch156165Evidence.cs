// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    // R156-R165: parser-attributed HTTP only; no packet Info as proof.
    internal static class NetworkBatch156165Evidence
    {
        internal static bool Http(TrafficRecord r) => NetworkBatch151155Evidence.HttpRequest(r) && Authority(r);
        internal static bool UriOf(TrafficRecord r, out Uri uri)
        {
            uri=null!;
            if(string.IsNullOrWhiteSpace(r.HttpUri)||r.HttpUri!.Length>2048) return false;
            if(Uri.TryCreate(r.HttpUri,UriKind.Absolute,out var absolute))
            {
                if(absolute.Scheme!="http"&&absolute.Scheme!="https"||!string.Equals(absolute.Host,r.HttpHost,StringComparison.OrdinalIgnoreCase))return false;
                uri=absolute;return true;
            }
            if(!r.HttpUri.StartsWith("/",StringComparison.Ordinal)||!Uri.TryCreate("https://placeholder"+r.HttpUri,UriKind.Absolute,out var relative))return false;
            uri=relative;return true;
        }
        internal static bool Path(TrafficRecord r,out string path)
        {
            path="";
            if(!UriOf(r,out var uri))return false;
            path=uri.AbsolutePath;
            return path.Length<=512&&!path.Contains("//",StringComparison.Ordinal);
        }
        internal static bool Segment(string path,string part)
            => path.Equals(part,StringComparison.OrdinalIgnoreCase)||path.StartsWith(part+"/",StringComparison.OrdinalIgnoreCase);
        internal static bool NamedPath(TrafficRecord r,params string[] parts)
            => Path(r,out var path)&&parts.Any(p=>Segment(path,p));
        private static bool JsonPart(string encoded,out JsonDocument? doc)
        {
            doc=null;
            if(encoded.Length is < 2 or > 2048||encoded.Any(c=>!(char.IsAsciiLetterOrDigit(c)||c is '-' or '_')))return false;
            try
            {
                var raw=encoded.Replace('-','+').Replace('_','/');
                raw=raw.PadRight((raw.Length+3)/4*4,'=');
                var bytes=Convert.FromBase64String(raw);
                if(bytes.Length is < 2 or > 1536)return false;
                doc=JsonDocument.Parse(bytes);
                if(doc.RootElement.ValueKind==JsonValueKind.Object)return true;
                doc.Dispose();doc=null;return false;
            }
            catch(Exception e) when(e is FormatException or JsonException){doc?.Dispose();doc=null;return false;}
        }
        internal static bool Jwt(string token,bool none)
        {
            if(token.Length is < 20 or > 4096)return false;
            var parts=token.Split('.');
            if(parts.Length!=3||parts[0].Length==0||parts[1].Length==0)return false;
            if(!JsonPart(parts[0],out var header))return false;
            using(header)
            {
                if(!header!.RootElement.TryGetProperty("alg",out var alg)||alg.ValueKind!=JsonValueKind.String)return false;
                var isNone=string.Equals(alg.GetString(),"none",StringComparison.OrdinalIgnoreCase);
                if(isNone!=none)return false;
                if(none?parts[2].Length!=0:parts[2].Length<8)return false;
                if(!none&&parts[2].Any(c=>!(char.IsAsciiLetterOrDigit(c)||c is '-' or '_')))return false;
                if(!JsonPart(parts[1],out var payload))return false;
                using(payload)return true;
            }
        }
        internal static IEnumerable<KeyValuePair<string,string>> Query(TrafficRecord r)
        {
            if(!UriOf(r,out var uri)||uri.Query.Length is < 3 or > 2048)yield break;
            foreach(var part in uri.Query.TrimStart('?').Split('&',StringSplitOptions.RemoveEmptyEntries))
            {
                var pair=part.Split('=',2);if(pair.Length!=2)continue;
                string name,value;
                try{name=Uri.UnescapeDataString(pair[0]);value=Uri.UnescapeDataString(pair[1]);}
                catch(UriFormatException){continue;}
                if(name is "jwt" or "id_token" or "access_token" or "assertion")
                    yield return new KeyValuePair<string,string>(name,value);
            }
        }
        internal static bool JwtNone(TrafficRecord r,out string source)
        {
            source="";
            foreach(var item in Query(r))if(Jwt(item.Value,true)){source="query_parameter";return true;}
            if(string.IsNullOrWhiteSpace(r.HttpRequestHeaders)||r.HttpRequestHeaders!.Length>8192)return false;
            foreach(var line in r.HttpRequestHeaders.Split('\n'))
            {
                var colon=line.IndexOf(':');
                if(colon<0||!line[..colon].Trim().Equals("Authorization",StringComparison.OrdinalIgnoreCase))continue;
                var value=line[(colon+1)..].Trim();
                if(value.StartsWith("Bearer ",StringComparison.OrdinalIgnoreCase)&&Jwt(value[7..].Trim(),true))
                {source="authorization_header";return true;}
            }
            return false;
        }
        internal static bool JwtQuery(TrafficRecord r,out string name)
        {
            name="";
            foreach(var item in Query(r))if(Jwt(item.Value,false)){name=item.Key;return true;}
            return false;
        }
        // A parser-provided Host cannot contradict a captured Host header.
        internal static bool Authority(TrafficRecord r)
        {
            if(string.IsNullOrWhiteSpace(r.HttpHost)||r.HttpHost!.Length>255)return false;
            var headers=r.HttpRequestHeaders;
            if(string.IsNullOrWhiteSpace(headers))return true;
            if(headers!.Length>8192)return false;
            var found=false;
            foreach(var line in headers.Split('\n'))
            {
                var index=line.IndexOf(':');
                if(index<0||!line[..index].Trim().Equals("Host",StringComparison.OrdinalIgnoreCase))continue;
                if(found||!line[(index+1)..].Trim().Equals(r.HttpHost,StringComparison.OrdinalIgnoreCase))return false;
                found=true;
            }
            return true;
        }
        internal static bool Docker(TrafficRecord r)
        {
            var host=r.HttpHost??"";
            var label=host.Split('.')[0];
            var docker=label.Equals("docker",StringComparison.OrdinalIgnoreCase)
                || label.StartsWith("docker-",StringComparison.OrdinalIgnoreCase);
            return (r.DestinationPort is 2375 or 2376 || docker)
                && NamedPath(r,"/containers/json","/containers/create","/images/json","/images/create","/version","/volumes","/networks","/swarm","/plugins");
        }
        internal static bool Cache(TrafficRecord r)
        {
            var label=(r.HttpHost??"").Split('.')[0];
            var named=label.Equals("redis",StringComparison.OrdinalIgnoreCase)
                || label.Equals("memcached",StringComparison.OrdinalIgnoreCase)
                || label.StartsWith("redis-",StringComparison.OrdinalIgnoreCase)
                || label.StartsWith("memcached-",StringComparison.OrdinalIgnoreCase);
            return (r.DestinationPort is 6379 or 11211 || named)
                && NamedPath(r,"/stats","/slabs","/items","/flush_all","/redis","/memcached");
        }
        internal static bool PhpInfo(TrafficRecord r)
            => Path(r,out var path)&&(path.Equals("/phpinfo.php",StringComparison.OrdinalIgnoreCase)
                || path.Equals("/phpinfo",StringComparison.OrdinalIgnoreCase));
        internal static bool Swagger(TrafficRecord r)=>NamedPath(r,"/swagger","/swagger-ui","/swagger-ui.html","/swagger.json","/openapi.json","/v3/api-docs","/v2/api-docs","/api-docs");
        internal static bool Actuator(TrafficRecord r)=>NamedPath(r,"/actuator/env","/actuator/heapdump","/actuator/jolokia","/actuator/metrics","/actuator/prometheus","/actuator/threaddump","/actuator/loggers","/actuator/beans","/actuator/mappings","/actuator/configprops","/actuator/scheduledtasks");
        internal static bool Kubernetes(TrafficRecord r)
        {
            var host=r.HttpHost??"";
            var hint=host.Equals("kubernetes",StringComparison.OrdinalIgnoreCase)||host.StartsWith("kubernetes.",StringComparison.OrdinalIgnoreCase)||host.StartsWith("k8s.",StringComparison.OrdinalIgnoreCase)||host.EndsWith(".svc.cluster.local",StringComparison.OrdinalIgnoreCase);
            return (r.DestinationPort==6443||hint)&&NamedPath(r,"/api/v1/namespaces","/api/v1/secrets","/api/v1/serviceaccounts","/apis/apps","/apis/rbac.authorization.k8s.io");
        }
    }
    // Per-rule-instance and per-source/target bounded duplicate/out-of-order guard.
    internal sealed class NetworkBatch156165ReplayGuard
    {
        private sealed class Slot{internal readonly Dictionary<Guid,DateTime> Ids=new();internal DateTime Latest=DateTime.MinValue;}
        private readonly object _gate=new();
        private readonly Dictionary<string,Slot> _slots=new(StringComparer.OrdinalIgnoreCase);
        internal bool Observe(TrafficRecord r,DateTime at)
        {
            if(r.Id==Guid.Empty)return false;
            var key=(r.Source??"")+"|"+(r.Destination??"")+"|"+(r.DestinationPort??0);
            lock(_gate)
            {
                foreach(var k in _slots.Where(x=>at-x.Value.Latest>TimeSpan.FromMinutes(15)).Select(x=>x.Key).ToArray())_slots.Remove(k);
                if(!_slots.TryGetValue(key,out var slot))
                {
                    if(_slots.Count>=1024)_slots.Remove(_slots.OrderBy(x=>x.Value.Latest).First().Key);
                    _slots[key]=slot=new Slot();
                }
                if(at<slot.Latest||slot.Ids.ContainsKey(r.Id))return false;
                foreach(var k in slot.Ids.Where(x=>at-x.Value>TimeSpan.FromMinutes(15)).Select(x=>x.Key).ToArray())slot.Ids.Remove(k);
                if(slot.Ids.Count>=256)slot.Ids.Remove(slot.Ids.OrderBy(x=>x.Value).First().Key);
                slot.Ids[r.Id]=at;slot.Latest=at;return true;
            }
        }
    }
}
