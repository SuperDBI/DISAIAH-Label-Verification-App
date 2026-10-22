FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN dotnet publish SecRev.csproj -c Release -o /out

FROM mcr.microsoft.com/dotnet/aspnet:10.0-bookworm-slim
WORKDIR /app
COPY --from=build /out/ ./
ENV SECREV_API=1 DOTNET_EnableDiagnostics=0
USER app
ENTRYPOINT ["dotnet", "SecRev.dll"]
