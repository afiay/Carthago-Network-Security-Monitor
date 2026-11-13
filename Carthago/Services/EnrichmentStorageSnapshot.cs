// SPDX-License-Identifier: MIT
namespace Carthago.Services;

public sealed record RegistryCapacitySnapshot(int Count, int Limit, long Rejected);
public sealed record CheckpointHealthSnapshot(long Writes, long Failures, string? LastError);
public sealed record EnrichmentStorageSnapshot(RegistryCapacitySnapshot Destinations, RegistryCapacitySnapshot Assets,
    CheckpointHealthSnapshot Checkpoints);
