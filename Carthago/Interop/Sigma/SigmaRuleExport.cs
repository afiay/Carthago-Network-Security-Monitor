// SPDX-License-Identifier: MIT
// File: Interop/Sigma/SigmaRuleExport.cs
using System.Collections.Generic;

namespace Carthago.Interop.Sigma
{
    public sealed class SigmaRuleExport
    {
        public string Title { get; set; } = string.Empty;
        public string Id { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public List<string> References { get; set; } = new();
        public List<string> Tags { get; set; } = new();
        public List<string> FalsePositives { get; set; } = new();
        public string Level { get; set; } = "low";
        public string SignalKind { get; set; } = string.Empty;
        public bool IsBehavioral { get; set; }
        public string ExportNote { get; set; } = string.Empty;
    }
}
