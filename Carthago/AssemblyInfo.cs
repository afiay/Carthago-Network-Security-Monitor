using System.Runtime.CompilerServices;
using System.Windows;

[assembly: InternalsVisibleTo("Carthago.Tests")]
// Preserve the former public model location for CLR type resolution.
[assembly: TypeForwardedTo(typeof(Carthago.Models.TrafficRecord))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.Flow.FlowKey))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.Flow.HandshakeBuffer))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.Flow.LatencyTracker))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.Iec104ApduInspector))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.Iec104FrameKind))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.Iec104ApduObservation))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.OpcUaConnectionInspector))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.OpcUaConnectionKind))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.OpcUaConnectionObservation))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.LdapMessageInspector))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.LdapMessageObservation))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.LdapSimpleBindObservation))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.TftpRequestInspector))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.TftpRequestKind))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.TftpTransferMode))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.TftpRequestObservation))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.BacnetBvlcControlInspector))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.BvlcControlFunction))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.BvlcControlObservation))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.BacnetDeviceCommunicationControlInspector))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.BacnetDeviceCommunicationControlObservation))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.BacnetWritePropertyInspector))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.BacnetWritePropertyObservation))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.Fingerprints.HttpJa4H))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.Fingerprints.TlsJa4))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.Fingerprints.TcpJa4T))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.Fingerprints.SshJa4SSH))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.Fingerprints.Hassh))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.Resp2CommandInspector))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.Resp2CommandKind))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.Resp2CommandObservation))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.Resp2SimpleReplyInspector))]
[assembly: TypeForwardedTo(typeof(Carthago.Services.ProtocolIntelligence.Resp2SimpleReplyKind))]

[assembly:ThemeInfo(
    ResourceDictionaryLocation.None,            //where theme specific resource dictionaries are located
                                                //(used if a resource is not found in the page,
                                                // or application resource dictionaries)
    ResourceDictionaryLocation.SourceAssembly   //where the generic resource dictionary is located
                                                //(used if a resource is not found in the page,
                                                // app, or any theme specific resource dictionaries)
)]
