using Carthago.Services;

namespace Carthago.Tests.TestInfrastructure;

internal sealed class PreferencesIsolation : IDisposable
{
    private readonly string _path;
    private readonly string? _originalContents;
    private readonly bool _hadOriginal;

    public PreferencesIsolation()
    {
        _path = Path.Combine(Path.GetTempPath(), "carthago-tests", $"{Guid.NewGuid():N}", "preferences.json");
        PreferencesService.SetFilePathOverride(_path);

        if (File.Exists(_path))
        {
            _originalContents = File.ReadAllText(_path);
            _hadOriginal = true;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        if (File.Exists(_path))
            File.Delete(_path);

        PreferencesService.Reset();
        PreferencesService.Load();
    }

    public void Dispose()
    {
        if (_hadOriginal)
            File.WriteAllText(_path, _originalContents!);
        else if (File.Exists(_path))
            File.Delete(_path);

        PreferencesService.SetFilePathOverride(null);
        PreferencesService.Load();
    }
}
