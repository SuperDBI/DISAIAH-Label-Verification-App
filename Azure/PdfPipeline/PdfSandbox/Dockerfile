FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY PdfSandbox/PdfSandbox.csproj PdfSandbox/
RUN dotnet restore PdfSandbox/PdfSandbox.csproj -a x64
COPY PdfSandbox/ PdfSandbox/
RUN dotnet publish PdfSandbox/PdfSandbox.csproj -c Release -a x64 -o /out --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /tmp/pdfwork \
    && chown app:app /tmp/pdfwork
WORKDIR /app
COPY --from=build /out/ ./
ENV ASPNETCORE_HTTP_PORTS=8080 \
    TMPDIR=/tmp/pdfwork \
    DOTNET_EnableDiagnostics=0
USER app
EXPOSE 8080
ENTRYPOINT ["dotnet", "PdfSandbox.dll"]
