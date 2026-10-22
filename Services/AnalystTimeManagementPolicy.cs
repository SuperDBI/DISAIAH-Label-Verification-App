using System;
using SecRev.Models;

namespace SecRev.Services;

internal static class AnalystTimeManagementPolicy
{
    public static readonly TimeSpan ReminderThreshold = TimeSpan.FromMinutes(5);

    public static bool ShouldPrompt(
        VaultRole? role,
        string? workflowStatus,
        bool isQueued,
        bool timerRunning,
        TimeSpan elapsed,
        bool alreadyPromptedThisSession) =>
        role == VaultRole.Analyst &&
        string.Equals(workflowStatus, "InReview", StringComparison.Ordinal) &&
        isQueued && timerRunning &&
        elapsed >= ReminderThreshold &&
        !alreadyPromptedThisSession;
}
