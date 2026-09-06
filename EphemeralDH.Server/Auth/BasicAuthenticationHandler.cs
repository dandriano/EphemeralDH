using System.Text.Encodings.Web;
using System.Security.Claims;
using System.Text;
using EphemeralDH.Server.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using System.Net.Http.Headers;
using System;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace EphemeralDH.Server.Auth;

public sealed class BasicAuthenticationHandler(
    IUserStore users,
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    private readonly IUserStore _users = users;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var values))
            return AuthenticateResult.NoResult();

        var header = values.ToString();
        if (string.IsNullOrWhiteSpace(header))
            return AuthenticateResult.NoResult();

        if (!AuthenticationHeaderValue.TryParse(header, out var parsed))
            return AuthenticateResult.Fail("Invalid Authorization header.");

        if (!"Basic".Equals(parsed.Scheme, StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.NoResult();

        if (string.IsNullOrWhiteSpace(parsed.Parameter))
            return AuthenticateResult.Fail("Missing Basic credentials.");

        byte[] credentialBytes;
        try
        {
            credentialBytes = Convert.FromBase64String(parsed.Parameter);
        }
        catch (FormatException)
        {
            return AuthenticateResult.Fail("Invalid Basic credentials encoding.");
        }

        var credential = Encoding.UTF8.GetString(credentialBytes);
        var idx = credential.IndexOf(':');
        if (idx <= 0)
            return AuthenticateResult.Fail("Invalid Basic credential format.");

        var usernameRaw = credential[..idx];
        var password = credential[(idx + 1)..];

        var username = DbInitializer.NormalizeUsername(usernameRaw);

        // Validate against PBKDF2 hash.
        var (ok, isAdmin) = await _users.ValidateCredentialsAsync(username, password, Context.RequestAborted);
        if (!ok)
            return AuthenticateResult.Fail("Invalid username or password.");

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, username),
            new("is_admin", isAdmin ? "1" : "0"),
        };

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);

        return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
    }
}

