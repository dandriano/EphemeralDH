using System.Text.Json;
using EphemeralDH.Middleware;
using EphemeralDH.Server.Auth;
using EphemeralDH.Server.Data;
using EphemeralDH.Server.Endpoints;
using EphemeralDH.Server.Middleware;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();

// SQLite-backed user store.
builder.Services.AddSingleton<ISqliteConnectionFactory, SqliteConnectionFactory>();
builder.Services.AddSingleton<DbInitializer>();
builder.Services.AddScoped<IUnitOfWork, SqliteUnitOfWork>();
builder.Services.AddScoped<IUserStore, SqliteUserStore>();
builder.Services.AddTransient<EdhxEncryptionMiddleware>();

// Basic auth.
builder.Services
    .AddAuthentication("Basic")
    .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("Basic", _ =>
    {
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("AuthenticatedUser", policy =>
    {
        policy.RequireAuthenticatedUser();
    })
    .AddPolicy("AuthenticatedAdmin", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.Requirements.Add(new IsAdminRequirement());
    });

builder.Services.AddSingleton<IAuthorizationHandler, IsAdminAuthorizationHandler>();
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

// Create schema + seed admin at startup.
using (var scope = app.Services.CreateScope())
{
    var initializer = scope.ServiceProvider.GetRequiredService<DbInitializer>();
    var connectionFactory = scope.ServiceProvider.GetRequiredService<ISqliteConnectionFactory>();
    initializer.InitializeAndSeedAdmin(connectionFactory);
}

app.UseAuthentication();
app.UseMiddleware<UnitOfWorkMiddleware>();
app.UseAuthorization();
app.UseMiddleware<EdhxEncryptionMiddleware>();

app.MapHealthChecks("/health");

app.MapPost("/users", AdminEndpoints.CreateUser)
    .Accepts<AdminEndpoints.CreateUserRequest>("application/json")
    .Produces(StatusCodes.Status201Created)
    .Produces(StatusCodes.Status400BadRequest)
    .Produces(StatusCodes.Status401Unauthorized)
    .Produces(StatusCodes.Status403Forbidden)
    .Produces(StatusCodes.Status409Conflict)
    .RequireAuthorization("AuthenticatedAdmin");

app.MapPost("/echo", SecureEndpoints.EchoEncrypted)
    .Accepts<JsonElement>("application/json")
    .RequireAuthorization("AuthenticatedUser")
    .RequireEdhxEncryption();

app.Run();
