using Microsoft.AspNetCore.Http;

namespace EphemeralDH.Middleware.Identity;

public sealed class BasicPrincipalIdentityResolver : IEdhxIdentityResolver
{
    public bool TryResolveUsername(HttpContext context, out string username)
    {
        username = context.User?.Identity?.Name ?? string.Empty;
        return !string.IsNullOrWhiteSpace(username);
    }
}

