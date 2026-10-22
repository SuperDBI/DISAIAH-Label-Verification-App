using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.Azure.Cosmos;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 26 * 1024 * 1024);
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 26 * 1024 * 1024;
    options.ValueLengthLimit = 16 * 1024;
    options.MultipartHeadersLengthLimit = 16 * 1024;
});
var storageUrl = builder.Configuration["Pipeline:StorageAccountUrl"];
var tenantId = builder.Configuration["Authentication:TenantId"];
var audience = builder.Configuration["Authentication:Audience"];
var containerName = builder.Configuration["Pipeline:QuarantineContainer"] ?? "quarantine";
var cosmosUrl = builder.Configuration["Pipeline:CosmosEndpoint"];
var cosmosDatabase = builder.Configuration["Pipeline:CosmosDatabase"] ?? "secrev";
var cosmosContainer = builder.Configuration["Pipeline:CosmosContainer"] ?? "documents";
if (!Uri.TryCreate(storageUrl, UriKind.Absolute, out var storageUri) || !Uri.TryCreate(cosmosUrl, UriKind.Absolute, out var cosmosUri) || string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(audience))
{
    throw new InvalidOperationException("Storage URL, Entra tenant ID, and API audience configuration are required.");
}

builder.Services.AddSingleton(new BlobServiceClient(storageUri, new DefaultAzureCredential()));
builder.Services.AddSingleton(new CosmosClient(cosmosUri.ToString(), new DefaultAzureCredential()));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.Authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
    options.Audience = audience;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        NameClaimType = "name",
        RoleClaimType = "roles"
    };
});
builder.Services.AddAuthorization(options => options.AddPolicy("DocumentUpload", policy =>
    policy.RequireAuthenticatedUser()
          .RequireClaim("tid", tenantId)
          .RequireRole("Document.Upload")));

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.Use(async (context, next) =>
{
    var originalBody = context.Response.Body;
    await using var boundedBody = new BoundedWriteStream(originalBody, 64 * 1024);
    context.Response.Body = boundedBody;
    var authenticatedRequest = context.Request.Path.StartsWithSegments("/api") && context.User.Identity?.IsAuthenticated == true;
    try
    {
        await next();
    }
    catch (InvalidDataException)
    {
        context.Response.Clear();
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new { title = "Invalid multipart request." });
    }
    catch (Exception) when (authenticatedRequest)
    {
        context.Response.Clear();
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await context.Response.WriteAsJsonAsync(new { title = "The request could not be completed." });
    }
    finally
    {
        context.Response.Body = originalBody;
    }
});

app.MapPost("/api/documents", async (HttpRequest request, BlobServiceClient blobs, CosmosClient cosmos, ClaimsPrincipal user, CancellationToken cancellationToken) =>
{
    if (!request.HasFormContentType)
        return Results.Problem(statusCode: StatusCodes.Status415UnsupportedMediaType, title: "Upload must be multipart/form-data.");

    var form = await request.ReadFormAsync(cancellationToken);
    var file = form.Files.GetFile("file");
    if (file is null || file.Length is <= 0 or > 25 * 1024 * 1024)
        return Results.Problem(statusCode: StatusCodes.Status413PayloadTooLarge, title: "PDF must be between 1 byte and 25 MiB.");
    if (!string.Equals(Path.GetExtension(file.FileName), ".pdf", StringComparison.OrdinalIgnoreCase))
        return Results.Problem(statusCode: StatusCodes.Status415UnsupportedMediaType, title: "Only PDF uploads are accepted.");

    var tenant = user.FindFirstValue("tid");
    if (!Guid.TryParse(tenant, out var tenantGuid))
        return Results.Forbid();

    var documentId = Guid.NewGuid();
    var blobName = $"{tenantGuid:N}/{documentId:N}.pdf";
    await using var stream = file.OpenReadStream();
    var header = new byte[5];
    var read = await stream.ReadAsync(header, cancellationToken);
    if (read != header.Length || !header.AsSpan().SequenceEqual("%PDF-"u8))
        return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "PDF header was not found.");
    stream.Position = 0;

    var container = blobs.GetBlobContainerClient(containerName);
    var blob = container.GetBlobClient(blobName);
    var metadata = new Dictionary<string, string>
    {
        ["tenantId"] = tenantGuid.ToString("N"),
        ["documentId"] = documentId.ToString("N"),
        ["uploadPrincipal"] = SafeMetadata(user.FindFirstValue("oid") ?? user.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown")
    };

    try
    {
        await blob.UploadAsync(stream, new BlobUploadOptions
        {
            HttpHeaders = new BlobHttpHeaders { ContentType = "application/pdf" },
            Metadata = metadata,
            Conditions = new BlobRequestConditions { IfNoneMatch = Azure.ETag.All }
        }, cancellationToken);
    }
    catch (Azure.RequestFailedException ex) when (ex.Status == 409 || ex.Status == 412)
    {
        return Results.Conflict(new { title = "Document identifier collision." });
    }

    var record = new UploadRecord
    {
        Id = documentId.ToString("N"),
        PartitionKey = tenantGuid.ToString("N"),
        TenantId = tenantGuid.ToString("N"),
        FileName = Path.GetFileName(file.FileName),
        BlobUri = blob.Uri.ToString(),
        Status = "QuarantinedAwaitingDefenderScan",
        UploadedAtUtc = DateTimeOffset.UtcNow
    };
    await cosmos.GetContainer(cosmosDatabase, cosmosContainer).CreateItemAsync(record, new PartitionKey(record.PartitionKey), cancellationToken: cancellationToken);

    // Uploads are quarantined. Never hand the blob URI to a parser or extraction API from this route.
    return Results.Accepted(value: new UploadAccepted(record.Id, record.Status, record.UploadedAtUtc));
})
.RequireAuthorization("DocumentUpload")
.DisableAntiforgery();

app.MapGet("/api/documents/{id}", async (string id, CosmosClient cosmos, ClaimsPrincipal user, CancellationToken cancellationToken) =>
{
    if (!Guid.TryParseExact(id, "N", out var documentGuid) || !Guid.TryParse(user.FindFirstValue("tid"), out var tenantGuid))
        return Results.NotFound();
    try
    {
        var response = await cosmos.GetContainer(cosmosDatabase, cosmosContainer)
            .ReadItemAsync<UploadRecord>(documentGuid.ToString("N"), new PartitionKey(tenantGuid.ToString("N")), cancellationToken: cancellationToken);
        var record = response.Resource;
        return Results.Ok(new DocumentStatusResponse(record.Id, record.FileName, record.Status, record.UploadedAtUtc, record.ProcessedAtUtc));
    }
    catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
    {
        return Results.NotFound();
    }
})
.RequireAuthorization("DocumentUpload");

app.MapGet("/health/live", () => Results.Ok(new { status = "live" }));
app.Run();

static string SafeMetadata(string value)
{
    var safe = new string(value.Where(char.IsAsciiLetterOrDigit).Take(64).ToArray());
    return safe.Length == 0 ? "unknown" : safe;
}

internal sealed record UploadAccepted(string DocumentId, string Status, DateTimeOffset UploadedAtUtc);
internal sealed record DocumentStatusResponse(string DocumentId, string FileName, string Status, DateTimeOffset UploadedAtUtc, DateTimeOffset? ProcessedAtUtc);

internal sealed class UploadRecord
{
    public required string Id { get; init; }
    public required string PartitionKey { get; init; }
    public required string TenantId { get; init; }
    public required string FileName { get; init; }
    public required string BlobUri { get; init; }
    public required string Status { get; set; }
    public DateTimeOffset UploadedAtUtc { get; init; }
    public DateTimeOffset? ProcessedAtUtc { get; set; }
}

internal sealed class BoundedWriteStream(Stream inner, long limit) : Stream
{
    private long _written;
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
    public override void Write(byte[] buffer, int offset, int count)
    {
        EnsureBounded(count);
        inner.Write(buffer, offset, count);
    }
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        EnsureBounded(buffer.Length);
        await inner.WriteAsync(buffer, cancellationToken);
    }
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        EnsureBounded(count);
        return inner.WriteAsync(buffer, offset, count, cancellationToken);
    }
    private void EnsureBounded(int count)
    {
        if (count < 0 || checked(_written + count) > limit) throw new InvalidDataException("Response size limit exceeded.");
        _written += count;
    }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
