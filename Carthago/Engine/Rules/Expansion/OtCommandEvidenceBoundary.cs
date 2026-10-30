// SPDX-License-Identifier: MIT
// GA R473-R480 — SOURCE CANDIDATE — UNVERIFIED.
// A wire-derived OT protocol label is framing recognition, not a decoded
// operation, response, asset authorization, or a validated anomaly baseline.
namespace Carthago.Engine.Rules.Expansion
{
    internal static class OtCommandEvidenceBoundary
    {
        internal static (string Code, string Detail)? GetMissingProducer(string ruleId)
            => ruleId switch
            {
                "R473" => ("MODBUS_DEVICE_ID_REQUEST_SERIES_UNAVAILABLE",
                    "The Modbus framing recognizer does not decode function 43/MEI 14 request identity, distinct targets, or a calibrated enumeration series."),
                "R474" => ("MODBUS_LISTEN_ONLY_SUBFUNCTION_UNAVAILABLE",
                    "Modbus framing alone cannot attest a client-to-server diagnostics function 08 subfunction 0004 request or distinguish an attempt from a response."),
                "R475" => ("MODBUS_DIAGNOSTICS_SUBFUNCTION_AND_POLICY_UNAVAILABLE",
                    "A Modbus label does not identify function 08 diagnostics subfunctions, risky action, approved engineering source, or outcome."),
                "R476" => ("MODBUS_COIL_WRITE_DISTINCT_BURST_UNAVAILABLE",
                    "The existing modbus.write classification groups several functions; it cannot prove coil-write function 05/15, distinct requests, or an anomalous burst."),
                "R477" => ("S7_CPU_CONTROL_COMMAND_UNAVAILABLE",
                    "S7comm framing is recognized but CPU start/stop operation, request direction, and approved engineering-session provenance are not decoded."),
                "R478" => ("S7_BLOCK_TRANSFER_OPERATION_UNAVAILABLE",
                    "S7comm framing cannot prove upload/download block operation, request/response correlation, or successful transfer; the original HTTP requirement is a separate contract mismatch."),
                "R479" => ("S7_PLC_IDENTIFICATION_REQUEST_UNAVAILABLE",
                    "S7comm framing does not identify a specific PLC identification request or a source-attributed enumeration sequence."),
                "R480" => ("DNP3_CROB_CONTROL_OPERATION_UNAVAILABLE",
                    "DNP3 link-layer CRC validation is not application-layer SELECT/OPERATE/CROB object decoding, approved-master attribution, or command outcome."),
                _ => null
            };
    }
}
