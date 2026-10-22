// SPDX-License-Identifier: MIT
// File: Services/EntityGraph/EntityGraphQuery.cs
namespace Carthago.Services.EntityGraph
{
    public sealed class EntityGraphQuery
    {
        public string? EntityId { get; set; }
        public EntityNodeKind? Kind { get; set; }
        public string? Contains { get; set; }
    }
}
