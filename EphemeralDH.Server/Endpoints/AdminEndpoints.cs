using System.Threading;
using System.Threading.Tasks;
using EphemeralDH.Server.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

namespace EphemeralDH.Server.Endpoints;

public static class AdminEndpoints
{
    public sealed record CreateUserRequest(string Username, string Password, bool IsAdmin);

    public sealed record CreateUserResponse(long Id, string Username, bool IsAdmin);

    public static async Task<IResult> CreateUser(
        CreateUserRequest request,
        [FromServices] IUserStore users,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || request.Username.Length is < 3 or > 64)
        {
            return Results.BadRequest(new { error = "username" });
        }
        if (string.IsNullOrWhiteSpace(request.Password) || request.Password.Length is < 8 or > 256)
        {
            return Results.BadRequest(new { error = "password" });
        }

        var normalized = DbInitializer.NormalizeUsername(request.Username);
        try
        {
            var created = await users.CreateUserAsync(normalized, request.Password, request.IsAdmin, ct);
            return Results.Created($"/api/admin/users/{created.Id}",
                new CreateUserResponse(created.Id, created.Username, created.IsAdmin));
        }
        catch (DuplicateUsernameException)
        {
            return Results.Conflict(new { error = "duplicate_username" });
        }
    }
}
