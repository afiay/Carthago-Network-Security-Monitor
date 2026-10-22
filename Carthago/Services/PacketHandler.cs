
< Project Sdk = "Microsoft.NET.Sdk" >

  < PropertyGroup >
    < OutputType > WinExe </ OutputType >
    < TargetFramework > net8.0 - windows </ TargetFramework >
    < UseWPF > true </ UseWPF >
    < Nullable > enable </ Nullable >
    < ImplicitUsings > enable </ ImplicitUsings >
    < RuntimeIdentifiers > win - x64; win - arm64 </ RuntimeIdentifiers >
  </ PropertyGroup >

  < !--Application dependencies-- >
  < ItemGroup >
    < PackageReference Include = "Azure.Identity" Version = "1.17.0" />
    < PackageReference Include = "Azure.Monitor.Ingestion" Version = "1.2.0" />
    < PackageReference Include = "Confluent.Kafka" Version = "2.11.1" />
    < PackageReference Include = "DotNetEnv" Version = "3.1.1" />
    < PackageReference Include = "LiteDB" Version = "5.0.16" />
    < PackageReference Include = "LLamaSharp" Version = "0.4.0" />
    < PackageReference Include = "MathNet.Numerics" Version = "5.0.0" />
    < PackageReference Include = "MaxMind.GeoIP2" Version = "5.3.0" />
    < PackageReference Include = "Microsoft.Diagnostics.Tracing.TraceEvent" Version = "3.1.28" />
    < PackageReference Include = "Microsoft.Extensions.Caching.Abstractions" Version = "9.0.10" />
    < PackageReference Include = "Microsoft.Extensions.Caching.Memory" Version = "9.0.10" />
    < PackageReference Include = "Microsoft.ML" Version = "3.0.1" />
    < PackageReference Include = "Microsoft.ML.TimeSeries" Version = "3.0.1" />
    < PackageReference Include = "Microsoft.Web.WebView2" Version = "1.0.3537.50" />
    < PackageReference Include = "OpenTelemetry" Version = "1.13.0" />
    < PackageReference Include = "OpenTelemetry.Exporter.OpenTelemetryProtocol" Version = "1.13.0" />
    < PackageReference Include = "OpenTelemetry.Extensions.Hosting" Version = "1.13.0" />
    < PackageReference Include = "QuikGraph" Version = "2.5.0" />
    < PackageReference Include = "ScottPlot.WPF" Version = "5.1.58" />
    < PackageReference Include = "SharpPcap" Version = "6.3.1" />
    < PackageReference Include = "PacketDotNet" Version = "1.4.8" />
    < PackageReference Include = "SnmpSharpNet" Version = "0.9.7" />
    < PackageReference Include = "SSH.NET" Version = "2025.1.0" />
    < PackageReference Include = "System.Management" Version = "9.0.10" />
    < PackageReference Include = "WhoisClient.NET" Version = "6.1.0" />
    < PackageReference Include = "YamlDotNet" Version = "16.3.0" />
  </ ItemGroup >

  < !--Legacy and test-source exclusions -->
  <ItemGroup>
    <Compile Remove="Services\RuleEngine.cs" />
    <Compile Remove="Tests\**\*.cs" />
  </ItemGroup>

  <!-- Exclude local environment files from project outputs -->
  <ItemGroup>
    <None Remove=".env;.env.*" />
    <Content Remove=".env;.env.*" />
  </ItemGroup>

  <!-- Application resources -->
  <ItemGroup>
    <Content Include="Data\ThreatIntel\**\*.*">
      <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
    </Content>

    <None Include="rules.json">
      <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
    </None>

    <None Include="service-names-port-numbers.csv">
      <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
    </None>

    <None Include="threatfeed_cache.json"
          Condition="Exists('threatfeed_cache.json')">
      <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
    </None>
  </ItemGroup>

  <!-- Geolocation resources -->
  <ItemGroup>
    <None Include="Data\GeoLite2-*.mmdb">
      <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
    </None>

    <None Include="Data\custom.geo.json"
          Condition="Exists('Data\custom.geo.json')">
      <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
    </None>
  </ItemGroup>

</Project>
