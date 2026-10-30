// SPDX-License-Identifier: MIT
// GA R481-R490 — SOURCE CANDIDATE — UNVERIFIED.
// TrafficRecord exposes bounded packet and protocol metadata, not validated
// application-layer industrial commands, outcomes or trusted asset policy.
// Keep these explicit evidence gaps separate from port/name signal scoring.
namespace Carthago.Engine.Rules.Expansion
{
    internal static class OtDeepOperationEvidenceBoundary
    {
        internal static (string Code, string Detail)? GetMissingProducer(string ruleId)
            => ruleId switch
            {
                "R481" => ("DNP3_FREEZE_COUNTER_APPLICATION_OPERATION_UNAVAILABLE",
                    "DNP3 link-layer CRC does not decode application freeze function, target counter objects, request direction, or approved-master context."),
                "R482" => ("IEC104_CONTROL_ASDU_AND_EXTERNAL_POLICY_UNAVAILABLE",
                    "No IEC 60870-5-104 I/S-frame ASDU control operation, cause-of-transmission, trusted master identity, or external-boundary authorization is decoded."),
                "R483" => ("OPCUA_BROWSE_REQUEST_SERIES_UNAVAILABLE",
                    "No OPC UA service-level Browse requests, distinct node targets, authenticated session, or calibrated burst baseline reach this rule."),
                "R484" => ("OPCUA_WRITE_SERVICE_REQUEST_UNAVAILABLE",
                    "An OPC UA port or HTTP method cannot attest a decoded Write service request, node identity, session authorization, or server outcome."),
                "R485" => ("BACNET_WRITEPROPERTY_CONFIRMED_REQUEST_UNAVAILABLE",
                    "BACnet BVLC/NPDU recognition does not decode a confirmed WriteProperty APDU with invoke ID, property target, request direction, and policy."),
                "R486" => ("BACNET_DEVICE_COMMUNICATION_CONTROL_REQUEST_UNAVAILABLE",
                    "No decoded BACnet DeviceCommunicationControl service request, target device, invoke ID, or approved maintenance context is available."),
                "R487" => ("PROFINET_DCP_SET_NAME_FRAME_UNAVAILABLE",
                    "No validated PROFINET DCP Set Name request with service/type, station name, L2 source, and authorized engineering station is produced."),
                "R488" => ("ETHERNETIP_LISTIDENTITY_DISTINCT_BURST_UNAVAILABLE",
                    "No decoded EtherNet/IP encapsulation ListIdentity command series, distinct transactions, trusted targets, or discovery-rate baseline exists."),
                "R489" => ("ETHERNETIP_CIP_FORWARDOPEN_AND_BOUNDARY_UNAVAILABLE",
                    "No validated EtherNet/IP CIP Forward_Open service, connection path, request direction, or trusted external-boundary authorization is produced."),
                "R490" => ("IEC61850_MMS_WRITE_OPERATION_UNAVAILABLE",
                    "TCP/102 and TPKT framing cannot establish IEC 61850 MMS Write service, named data object, authenticated association, or outcome."),
                _ => null
            };
    }
}
