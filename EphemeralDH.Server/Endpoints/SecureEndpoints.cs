using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace EphemeralDH.Server.Endpoints;

public static class SecureEndpoints
{
    public static Task<IResult> EchoEncrypted(
        JsonElement body,
        CancellationToken ct)
    {
        // Middleware encrypts the response body; we just round-trip the JSON payload.
        return Task.FromResult(Results.Json(body));
    }
}
