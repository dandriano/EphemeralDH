using Microsoft.AspNetCore.Http;

namespace EphemeralDH.Middleware.Identity;

public interface IEdhxIdentityResolver
{
    bool TryResolveUsername(HttpContext context, out string username);
}

