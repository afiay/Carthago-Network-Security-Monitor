// SPDX-License-Identifier: MIT
using System.IO.Compression;
using System.Text.Json;
using Carthago.Cli;
using Carthago.Services.SessionFiles;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableCoreArchitectureTests
{
    [Fact]
    public void ArchiveTypesAreOwnedByOnePortableAssembly()
    {
        var assembly = typeof(CarthagoSessionSnapshot).Assembly;
        Assert.Equal("Carthago.Core", assembly.GetName().Name);
        Assert.Same(assembly, typeof(CarthagoSessionArchiveService).Assembly);
        Assert.NotSame(assembly, typeof(CliApplication).Assembly);
        Assert.DoesNotContain(assembly.GetReferencedAssemblies(), reference =>
            reference.Name is "Carthago" or "PresentationFramework" or "PresentationCore" or "WindowsBase");
    }

    [Fact]
    public async Task SharedArchiveRoundTripAndCliInspectionPreserveRedaction()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".csa");
        try
        {
            var snapshot = CarthagoSessionSnapshot.CreateEmpty();
            snapshot.AddRows("Traffic", new[] { new { Source = "192.0.2.1", Password = "secret-fixture" } });
            var service = new CarthagoSessionArchiveService();
            await service.SaveAsync(path, snapshot);
            var opened = await service.OpenAsync(path);
            var row = Assert.Single(opened.Categories["Traffic"]);
            Assert.Equal("192.0.2.1", row.GetProperty("Source").GetString());
            Assert.Equal("[REDACTED]", row.GetProperty("Password").GetString());
            using var output = new StringWriter();
            using var error = new StringWriter();
            Assert.Equal(CliApplication.Success, await CliApplication.RunAsync(
                new[] { "session", "inspect", path, "--json" }, output, error));
            using var json = JsonDocument.Parse(output.ToString());
            Assert.Equal(1, json.RootElement.GetProperty("archiveVersion").GetInt32());
            Assert.DoesNotContain("secret-fixture", output.ToString());
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task ModifiedArchiveEntryFailsIntegrityValidation()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".csa");
        try
        {
            var service = new CarthagoSessionArchiveService();
            await service.SaveAsync(path, CarthagoSessionSnapshot.CreateEmpty());
            using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            {
                zip.GetEntry("data/Traffic.json")!.Delete();
                using var writer = new StreamWriter(zip.CreateEntry("data/Traffic.json").Open());
                await writer.WriteAsync("[{}]");
            }
            await Assert.ThrowsAsync<InvalidDataException>(() => service.OpenAsync(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task CancelledSaveDoesNotReplaceExistingArchive()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".csa");
        try
        {
            var service = new CarthagoSessionArchiveService();
            await service.SaveAsync(path, CarthagoSessionSnapshot.CreateEmpty());
            byte[] original = await File.ReadAllBytesAsync(path);
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                service.SaveAsync(path, CarthagoSessionSnapshot.CreateEmpty(), cancellation.Token));
            Assert.Equal(original, await File.ReadAllBytesAsync(path));
        }
        finally { File.Delete(path); }
    }
}
