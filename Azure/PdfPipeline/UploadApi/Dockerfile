FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY UploadApi/PdfPipeline.UploadApi.csproj UploadApi/
RUN dotnet restore UploadApi/PdfPipeline.UploadApi.csproj
COPY UploadApi/ UploadApi/
RUN dotnet publish UploadApi/PdfPipeline.UploadApi.csproj -c Release -o /out --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS final
WORKDIR /app
COPY --from=build /out/ ./
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0
USER app
EXPOSE 8080
ENTRYPOINT ["dotnet", "PdfPipeline.UploadApi.dll"]
