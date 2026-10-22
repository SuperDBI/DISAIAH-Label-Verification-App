using System;
using System.Runtime.InteropServices;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;

namespace SecRev.Services;

/// <summary>
/// Best-effort, app-scoped RASP controls. This class never reads clipboard data
/// and does not install system-wide hooks.
/// </summary>
internal static class RuntimeApplicationProtection
{
    private const uint WindowDisplayAffinityNone = 0x00;
    private const uint WindowDisplayAffinityMonitor = 0x01;
    private const uint WindowDisplayAffinityExcludeFromCapture = 0x11;

    public static void Attach(Window window, Action<string> onCaptureStatus, Action<string> onClipboardAction)
    {
        window.AddHandler(
            InputElement.KeyDownEvent,
            (_, args) => HandleKeyDown(args, onClipboardAction),
            RoutingStrategies.Tunnel,
            handledEventsToo: true);
        window.AddHandler(
            InputElement.ContextRequestedEvent,
            (_, args) =>
            {
                if (!IsTextBoxSource(args.Source)) return;
                args.Handled = true;
                onClipboardAction("context-menu");
            },
            RoutingStrategies.Tunnel,
            handledEventsToo: true);
        window.Opened += (_, _) => onCaptureStatus(ApplyCaptureProtection(window));
    }

    private static void HandleKeyDown(KeyEventArgs args, Action<string> onClipboardAction)
    {
        if (!IsTextBoxSource(args.Source)) return;

        var modifiers = args.KeyModifiers;
        var hasControl = (modifiers & KeyModifiers.Control) != 0;
        var hasMeta = (modifiers & KeyModifiers.Meta) != 0;
        var hasShift = (modifiers & KeyModifiers.Shift) != 0;
        var hasClipboardModifier = hasControl || hasMeta;

        var action = args.Key switch
        {
            Key.C when hasClipboardModifier => "copy",
            Key.X when hasClipboardModifier => "cut",
            Key.V when hasClipboardModifier => "paste",
            Key.Insert when hasControl => "copy",
            Key.Insert when hasShift => "paste",
            Key.Delete when hasShift => "cut",
            _ => null
        };

        if (action is null) return;
        args.Handled = true;
        onClipboardAction(action);
    }

    private static bool IsTextBoxSource(object? source)
    {
        for (var control = source as Control; control is not null; control = control.Parent as Control)
        {
            if (control is TextBox) return true;
        }
        return false;
    }

    private static string ApplyCaptureProtection(Window window)
    {
        if (!OperatingSystem.IsWindows())
            return "Screen capture restriction: unavailable on this platform; OS-specific protection is not implemented.";

        try
        {
            var platformHandle = window.TryGetPlatformHandle();
            if (platformHandle is null || !string.Equals(platformHandle.HandleDescriptor, "HWND", StringComparison.OrdinalIgnoreCase))
                return "Screen capture restriction: unavailable (native HWND not exposed by the current window backend).";

            if (SetWindowDisplayAffinity(platformHandle.Handle, WindowDisplayAffinityExcludeFromCapture))
                return "Screen capture restriction: Windows WDA_EXCLUDEFROMCAPTURE requested (best effort).";

            var excludeError = Marshal.GetLastWin32Error();
            if (SetWindowDisplayAffinity(platformHandle.Handle, WindowDisplayAffinityMonitor))
                return $"Screen capture restriction: Windows WDA_MONITOR fallback active (best effort; exclude request error {excludeError}).";

            var fallbackError = Marshal.GetLastWin32Error();
            return $"Screen capture restriction: Windows rejected both affinity settings (errors {excludeError}/{fallbackError}).";
        }
        catch (DllNotFoundException)
        {
            return "Screen capture restriction: Windows user32 API unavailable.";
        }
        catch (EntryPointNotFoundException)
        {
            return "Screen capture restriction: Windows display-affinity API unavailable.";
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            return "Screen capture restriction: could not apply Windows display affinity.";
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowDisplayAffinity(IntPtr windowHandle, uint affinity);
}
