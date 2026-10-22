// SPDX-License-Identifier: MIT
// File: Services/InvestigationCopilot/IInvestigationCopilot.cs
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services.InvestigationCopilot
{
    public interface IInvestigationCopilot
    {
        Task<CopilotAnswer> AnswerAsync(CopilotContextPack context, string question, CancellationToken cancellationToken = default);
    }
}
