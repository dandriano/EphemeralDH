using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace EphemeralDH.Server.Auth;

public sealed class IsAdminRequirement : IAuthorizationRequirement;

public sealed class IsAdminAuthorizationHandler : AuthorizationHandler<IsAdminRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, IsAdminRequirement requirement)
    {
        var isAdminClaim = context.User.FindFirstValue("is_admin");
        if (isAdminClaim == "1")
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}

