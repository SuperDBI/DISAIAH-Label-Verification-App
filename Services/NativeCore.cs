using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Reflection;

namespace SecRev.Services;

[Obfuscation(Exclude = false, ApplyToMembers = true)]
internal static class NativeCore
{
    private const string LibraryName = "secrev_native";

    [DllImport(LibraryName, EntryPoint = "secrev_can_access", CallingConvention = CallingConvention.Cdecl)]
    private static extern int CanAccessNative(int roleLevel, int requiredPriority);

    [DllImport(LibraryName, EntryPoint = "secrev_analyze_text", CallingConvention = CallingConvention.Cdecl)]
    private static extern int AnalyzeTextNative([MarshalAs(UnmanagedType.LPUTF8Str)] string text, out int words, out int emails, out int numberGroups);

    [DllImport(LibraryName, EntryPoint = "secrev_scan_text", CallingConvention = CallingConvention.Cdecl)]
    private static extern int ScanTextNative([MarshalAs(UnmanagedType.LPUTF8Str)] string text, out int findingCount, out uint findingFlags);

    [DllImport(LibraryName, EntryPoint = "secrev_count_matches", CallingConvention = CallingConvention.Cdecl)]
    private static extern int CountMatchesNative([MarshalAs(UnmanagedType.LPUTF8Str)] string text, [MarshalAs(UnmanagedType.LPUTF8Str)] string query, out int matchCount);

    public static bool CanAccess(int roleLevel, int requiredPriority) => CanAccessNative(roleLevel, requiredPriority) == 1;

    public static TextAnalysis Analyze(string text)
    {
        if (AnalyzeTextNative(text, out var words, out var emails, out var numberGroups) != 1)
        {
            throw new InvalidOperationException("The native analysis core rejected the input.");
        }

        return new TextAnalysis(words, emails, numberGroups);
    }

    public static ScanAnalysis Scan(string text)
    {
        if (ScanTextNative(text, out var count, out var flags) != 1)
        {
            throw new InvalidOperationException("The native defensive scan rejected the input.");
        }

        string[] signatures = { "script tag", "javascript URL", "PowerShell reference", "cmd.exe reference", "eval() call", "onerror handler", "onload handler" };
        var findings = new List<string>();
        for (var i = 0; i < signatures.Length; i++)
        {
            if ((flags & (1u << i)) != 0)
            {
                findings.Add(signatures[i]);
            }
        }
        return new ScanAnalysis(count, findings);
    }

    public static int CountMatches(string text, string query)
    {
        if (string.IsNullOrWhiteSpace(query) || query.Length > 256)
        {
            throw new ArgumentException("Enter a match term of 1–256 characters.", nameof(query));
        }
        if (CountMatchesNative(text, query, out var count) != 1)
        {
            throw new InvalidOperationException("The native match operation rejected the input.");
        }
        return count;
    }
}

internal sealed record TextAnalysis(int Words, int EmailCandidates, int NumberGroups);
internal sealed record ScanAnalysis(int FindingCount, IReadOnlyList<string> Findings);
