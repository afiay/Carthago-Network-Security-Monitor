// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules.Expansion;

namespace Carthago.Engine.Rules;

/// <summary>Compiled portable execution catalog, not a live registry or qualification ledger.</summary>
internal static class PortableRuleCatalog
{
    internal delegate WebSignatureObservation Evaluator(PacketEvaluationContext context,out string method);

    internal sealed record Capability(string RuleId,string Name,string Status,
        IReadOnlyList<string> ExecutionEnvironments,IReadOnlyList<string> RequiredEvidence,
        IReadOnlyList<string> HttpMethods,string StateScope,int? CooldownSeconds,
        string Qualification,string WindowsRuntimePolicy,string Registration,string? Reason);

    private sealed record Registration(Capability Capability,Func<Evaluator> Factory);

    private static readonly IReadOnlyList<string> Environments=Array.AsReadOnly(new[]{"pcap","pcapng"});
    private static readonly IReadOnlyList<string> Evidence=Array.AsReadOnly(new[]{
        "packet.id","timestamp.utc","source.ip","destination.ip","source.port","destination.port",
        "tcp","http.method","http.uri","coherent_cleartext_http"});
    private static readonly IReadOnlyList<string> Get=Array.AsReadOnly(new[]{"GET"});
    private static readonly IReadOnlyList<string> GetPost=Array.AsReadOnly(new[]{"GET","POST"});

    private static Capability Supported(string id,string name,IReadOnlyList<string> methods) =>
        new(id,name,"supported",Environments,Evidence,methods,"capture_section_interface_clock_epoch_per_rule",
            600,"not_assessed","not_evaluated_by_replay","not_assessed",null);

    // Metadata and constructor are co-located. Every new registration becomes
    // discoverable and executable; fresh factories never share cooldown state.
    private static readonly Registration[] Entries =
    {
        new(Supported("R586","WordPress wp2shell plugin access request",GetPost),()=>new PortableR586Detector().Evaluate),
        new(Supported("R587","ScreenConnect SetupWizard path request",Get),()=>new PortableR587Detector().Evaluate),
        new(Supported("R588","SolarWinds SUPERNOVA handler request",GetPost),()=>new PortableR588Detector().Evaluate),
        new(Supported("R589","WebLogic keystore script request",GetPost),()=>new PortableR589Detector().Evaluate),
        new(Supported("R590","Rejetto HFS search injection request",Get),()=>new PortableR590Detector().Evaluate),
        new(Supported("R591","ADSelfService suspicious endpoint request",GetPost),()=>new PortableR591Detector().Evaluate),
        new(Supported("R592","DEWMODE webshell-shaped query request",GetPost),()=>new PortableR592Detector().Evaluate),
        new(Supported("R593","Apache Spark doAs backtick request",GetPost),()=>new PortableR593Detector().Evaluate),
        new(Supported("R594","Bitbucket archive exec-prefix request",GetPost),()=>new PortableR594Detector().Evaluate),
        new(Supported("R595","Grafana plugin traversal request",GetPost),()=>new PortableR595Detector().Evaluate)
    };

    private static readonly IReadOnlyList<Capability> Capabilities =
        Array.AsReadOnly(Entries.Select(e=>e.Capability).ToArray());

    internal static IReadOnlyList<Capability> All => Capabilities;
    internal static Capability? Find(string id)=>Capabilities.FirstOrDefault(c=>c.RuleId==id);

    internal static Capability Describe(string id)=>Find(id) ??
        new(id,"","unsupported_detector",Array.Empty<string>(),Array.Empty<string>(),Array.Empty<string>(),
            "not_assessed",null,"not_assessed","not_assessed","not_assessed","no_portable_detector_registered");

    internal static Dictionary<string,Evaluator> CreateEvaluators() =>
        Entries.ToDictionary(e=>e.Capability.RuleId,e=>e.Factory(),StringComparer.Ordinal);
}
