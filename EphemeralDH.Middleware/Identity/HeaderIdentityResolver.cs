using Microsoft.AspNetCore.Http;

namespace EphemeralDH.Middleware.Identity;

public sealed class HeaderIdentityResolver : IEdhxIdentityResolver
{
    private readonly string _headerName;

    public HeaderIdentityResolver(string headerName = "X-EDHX-Username")
        => _headerName = headerName;

    public bool TryResolveUsername(HttpContext context, out string username)
    {
        username = string.Empty;
        if (!context.Request.Headers.TryGetValue(_headerName, out var values))
        {
            return false;
        }

        var candidate = values.ToString();
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        username = candidate;
        return true;
    }
}

