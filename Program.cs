using Avalonia;
using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Hosting;
using SecRev.Services;

namespace SecRev;

class Program
{
    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static int Main(string[] args)
    {
        // Headless API mode for container hosting (e.g. Render); the desktop UI is the default.
        if (Array.Exists(args, a => a == "--api") || Environment.GetEnvironmentVariable("SECREV_API") == "1")
        {
            RunApi(args);
            return 0;
        }
        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    private const int MaxInputChars = 1_000_000;

    private static void RunApi(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        // Render supplies PORT; bind to all interfaces inside the container.
        if (Environment.GetEnvironmentVariable("PORT") is { Length: > 0 } port)
        {
            builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
        }
        builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 4 * 1024 * 1024);
        var app = builder.Build();

        app.MapGet("/", (HttpContext ctx) =>
        {
            ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'";
            ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
            return Results.Content(ApiWebPage.Html, "text/html; charset=utf-8");
        });
        app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

        app.MapPost("/process", (ProcessRequest? request) =>
        {
            if (request?.Text is not { Length: > 0 } text || text.Length > MaxInputChars)
            {
                return Results.BadRequest(new { error = $"'text' is required and must be 1-{MaxInputChars} characters." });
            }
            try
            {
                var analysis = NativeCore.Analyze(text);
                var scan = NativeCore.Scan(text);
                return Results.Ok(new { analysis, scan });
            }
            catch (Exception ex) when (ex is InvalidOperationException or DllNotFoundException or EntryPointNotFoundException)
            {
                return Results.Problem("Native processing failed.", statusCode: 500);
            }
        });

        app.Run();
    }

    private sealed record ProcessRequest(string? Text);

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
#if DEBUG
            .WithDeveloperTools()
#endif
            .WithInterFont()
            .LogToTrace();
}
