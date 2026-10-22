using System.IO;
using System.Reflection;
using Carthago.Services;
using Carthago.Services.Baseline;
using Xunit.Sdk;

namespace Carthago.Tests.TestInfrastructure;

[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class | AttributeTargets.Method)]
internal sealed class ResetSharedDetectionStateAttribute : BeforeAfterTestAttribute
{
    private static readonly string BaselineDirectory = Path.Combine(
        Path.GetTempPath(),
        "carthago-tests",
        "baseline",
        Guid.NewGuid().ToString("N"));

    public override void Before(MethodInfo methodUnderTest)
    {
        BaselineStore.SetCurrent(new BaselineStore(new BaselineOptions
        {
            DirectoryPath = BaselineDirectory
        }));
        RuleEngine.ResetRuntimeStateForReplay();
    }

    public override void After(MethodInfo methodUnderTest)
        => RuleEngine.ResetRuntimeStateForReplay();
}
