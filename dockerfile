FROM mcr.microsoft.com/dotnet/sdk:8.0-jammy AS build
WORKDIR /src

COPY EphemeralDH.Core/ EphemeralDH.Core/
COPY EphemeralDH.Middleware/ EphemeralDH.Middleware/
COPY EphemeralDH.Server/ EphemeralDH.Server/

RUN dotnet publish EphemeralDH.Server -c Release -p:PublishTrimmed=true --self-contained -o /app

FROM mcr.microsoft.com/dotnet/runtime-deps:8.0-jammy-chiseled AS runtime
ENV EDHX_ADMIN_USERNAME="admin"
ENV EDHX_ADMIN_PASSWORD="admin"
USER app
WORKDIR /app
COPY --from=build /app ./
EXPOSE 5555
ENTRYPOINT ["./EphemeralDH.Server"]