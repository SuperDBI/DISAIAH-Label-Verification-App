# Build a self-contained worker image. Pin base images and package versions in production CI.
FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Worker/PdfPipeline.Worker.csproj Worker/
RUN dotnet restore Worker/PdfPipeline.Worker.csproj -a x64
COPY Worker/ Worker/
RUN dotnet publish Worker/PdfPipeline.Worker.csproj -c Release -a x64 -o /out --no-restore

FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/runtime:10.0-bookworm-slim AS final
RUN mkdir -p /work \
    && chown app:app /work
WORKDIR /app
COPY --from=build /out/ ./
ENV TMPDIR=/work \
    DOTNET_EnableDiagnostics=0
USER app
ENTRYPOINT ["dotnet", "PdfPipeline.Worker.dll"]
