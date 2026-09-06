using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using EphemeralDH.Core;
using EphemeralDH.Middleware.Headers;
using EphemeralDH.Middleware.Identity;
using Microsoft.AspNetCore.Http;

namespace EphemeralDH.Middleware;

public sealed class EdhxEncryptionMiddleware(IEdhxIdentityResolver identityResolver) : IMiddleware
{
    private readonly IEdhxIdentityResolver _identityResolver = identityResolver;

    public EdhxEncryptionMiddleware() : this(new BasicPrincipalIdentityResolver())
    {
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var endpoint = context.GetEndpoint();
        var wantsEncryption =
            endpoint?.Metadata.Any(m => m is EncryptionRequiredMetadata) == true;

        if (!wantsEncryption)
        {
            await next(context);
            return;
        }

        // Fail closed on missing/invalid client identity.
        if (!_identityResolver.TryResolveUsername(context, out var username) ||
            string.IsNullOrWhiteSpace(username))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        // Core expects protocol headers via adapters.
        var requestHeadersAdapter = new HttpRequestHeadersAdapter(context.Request);
        byte[] clientPublicKey;
        try
        {
            clientPublicKey = ProtocolCodec.ReadClientPublicKey(requestHeadersAdapter);
        }
        catch (CryptographicException)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        // Encrypt only on successful responses.
        var originalBody = context.Response.Body;
        await using var memory = new MemoryStream();
        context.Response.Body = memory;

        try
        {
            await next(context);
        }
        finally
        {
            context.Response.Body = originalBody;
        }

        if (context.Response.StatusCode < 200 || context.Response.StatusCode >= 300)
        {
            // Keep plaintext response for errors/non-success.
            memory.Position = 0;
            await memory.CopyToAsync(originalBody, context.RequestAborted);
            return;
        }

        // If there is no response body, nothing to encrypt.
        if (memory.Length == 0)
            return;

        var plaintext = memory.ToArray();

        // Derive session values from transcript binding.
        var requestSalt = CryptoCore.DeriveRequestSalt(context.Request.Method, context.Request.Path, username);
        using var server = CryptoCore.CreateEphemeralKey();
        var sharedSecret = CryptoCore.DeriveSharedSecret(server, clientPublicKey);

        // HKDF info = UTF8(request.Path)
        var info = Encoding.UTF8.GetBytes(context.Request.Path);
        var sessionKey = CryptoCore.DeriveSessionKey(sharedSecret, requestSalt, info);

        // protocol version + method + path + username
        var aad = CryptoCore.BuildAssociatedData(CryptoCore.ProtocolVersion, context.Request.Method, context.Request.Path, username);

        var nonce = RandomNumberGenerator.GetBytes(CryptoCore.NonceLength);
        var ciphertext = CryptoCore.EncryptResponse(sessionKey, plaintext, nonce, aad, out var tag);

        var responseHeadersAdapter = new HttpResponseHeadersAdapter(context.Response);
        var responseEnvelope = CryptoCore.CreateServerResponse(
            CryptoCore.EncodePublicKey(server.PublicKey),
            nonce,
            tag,
            CryptoCore.ProtocolVersion);
        ProtocolCodec.SetServerResponseHeaders(responseHeadersAdapter, responseEnvelope);

        context.Response.ContentType = "application/octet-stream";
        context.Response.ContentLength = ciphertext.Length;
        
        await originalBody.WriteAsync(ciphertext, context.RequestAborted);
    }
}
