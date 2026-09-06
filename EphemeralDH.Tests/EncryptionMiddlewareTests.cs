using System;
using System.Linq;
using System.Net;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using EphemeralDH.Core;
using EphemeralDH.Middleware;


namespace EphemeralDH.Tests;

public class EncryptionMiddlewareTests
{
    private static void MarkAsEdhxEncryptedEndpoint(DefaultHttpContext context)
    {
        var metadataType = typeof(EdhxEncryptionMiddleware).Assembly.GetType(
            "EphemeralDH.Middleware.EncryptionRequiredMetadata",
            throwOnError: true);
        var metadataInstance = Activator.CreateInstance(metadataType!)!;

        var endpoint = new Endpoint(
            _ => Task.CompletedTask,
            new EndpointMetadataCollection([metadataInstance]),
            displayName: "edhx-secure");

        context.SetEndpoint(endpoint);
    }

    private static async Task InvokeAsync(EdhxEncryptionMiddleware middleware,
        DefaultHttpContext context,
        RequestDelegate next)
    {
        await middleware.InvokeAsync(context, next);
    }

    [Fact]
    public async Task SecureEndpoint_EncryptsResponse_AndDecryptsWithReturnedHeaders()
    {
        const string username = "alice";
        const string path = "/api/secure";
        const string plaintextText = "response-body";
        var plaintext = Encoding.UTF8.GetBytes(plaintextText);

        using var clientKey = Crypto.CreateEphemeralKey();
        var clientPublicKey = Crypto.EncodePublicKey(clientKey.PublicKey);

        var middleware = new EdhxEncryptionMiddleware();
        var context = new DefaultHttpContext();
        MarkAsEdhxEncryptedEndpoint(context);
        context.Response.Body = new MemoryStream();
        context.Request.Method = "POST";
        context.Request.Path = path;

        context.User = new ClaimsPrincipal(
            new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, username) }, authenticationType: "test"));
        context.Request.Headers[Codec.ClientPublicKeyHeader] = Convert.ToBase64String(clientPublicKey);

        // `next` writes the plaintext body and sets 2xx status.
        static Task next(HttpContext ctx)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            return ctx.Response.WriteAsync(plaintextText);
        }

        await InvokeAsync(middleware, context, next);

        Assert.Equal((int)HttpStatusCode.OK, context.Response.StatusCode);
        Assert.True(context.Response.Headers.ContainsKey(Codec.ServerPublicKeyHeader));
        Assert.True(context.Response.Headers.ContainsKey(Codec.NonceHeader));
        Assert.True(context.Response.Headers.ContainsKey(Codec.TagHeader));
        Assert.True(context.Response.Headers.ContainsKey(Codec.ProtocolVersionHeader));

        var cipherBytes = ReadResponseBody(context);
        Assert.False(plaintext.SequenceEqual(cipherBytes));

        var serverPublicKeyB64 = context.Response.Headers[Codec.ServerPublicKeyHeader].ToString();
        var serverNonceB64 = context.Response.Headers[Codec.NonceHeader].ToString();
        var tagB64 = context.Response.Headers[Codec.TagHeader].ToString();
        var protocolVersion = context.Response.Headers[Codec.ProtocolVersionHeader].ToString();

        var serverEphemeralPublicKey = Convert.FromBase64String(serverPublicKeyB64);
        var nonce = Convert.FromBase64String(serverNonceB64);
        var tag = Convert.FromBase64String(tagB64);

        Assert.Equal(Crypto.ProtocolVersion, protocolVersion);

        // Compute client side session key using server ephemeral public key.
        var sharedSecret = Crypto.DeriveSharedSecret(clientKey, serverEphemeralPublicKey);
        var requestSalt = Crypto.DeriveRequestSalt("POST", path, username);
        var info = Encoding.UTF8.GetBytes(path); // must match middleware
        var clientSessionKey = Crypto.DeriveSessionKey(sharedSecret, requestSalt, info);
        var aad = Crypto.BuildAssociatedData(Crypto.ProtocolVersion, "POST", path, username);

        var decrypted = Crypto.DecryptResponse(clientSessionKey, cipherBytes, nonce, tag, aad);
        Assert.True(decrypted.SequenceEqual(plaintext));
    }

    [Fact]
    public async Task SecureEndpoint_MissingIdentity_Returns401_AndNoEdhxHeaders()
    {
        var middleware = new EdhxEncryptionMiddleware();
        var context = new DefaultHttpContext();
        MarkAsEdhxEncryptedEndpoint(context);
        context.Response.Body = new MemoryStream();
        context.Request.Method = "POST";
        context.Request.Path = "/api/something";

        // Provide only client public key, but omit identity.
        using var key = Crypto.CreateEphemeralKey();
        var clientPublicKey = Crypto.EncodePublicKey(key.PublicKey);
        context.Request.Headers[Codec.ClientPublicKeyHeader] = Convert.ToBase64String(clientPublicKey);

        static Task next(HttpContext ctx)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            return ctx.Response.WriteAsync("should-not-run");
        }

        await InvokeAsync(middleware, context, next);

        Assert.Equal((int)HttpStatusCode.Unauthorized, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey(Codec.ServerPublicKeyHeader));
        Assert.False(context.Response.Headers.ContainsKey(Codec.NonceHeader));
        Assert.False(context.Response.Headers.ContainsKey(Codec.TagHeader));
        Assert.False(context.Response.Headers.ContainsKey(Codec.ProtocolVersionHeader));
    }

    [Fact]
    public async Task SecureEndpoint_MissingClientPublicKey_Returns401_AndNoEdhxHeaders()
    {
        const string username = "alice";

        var middleware = new EdhxEncryptionMiddleware();
        var context = new DefaultHttpContext();
        MarkAsEdhxEncryptedEndpoint(context);
        context.Response.Body = new MemoryStream();
        context.Request.Method = "POST";
        context.Request.Path = "/api/something";

        context.User = new ClaimsPrincipal(
            new ClaimsIdentity([new Claim(ClaimTypes.Name, username)], authenticationType: "test"));

        static Task next(HttpContext ctx)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            return ctx.Response.WriteAsync("should-not-run");
        }

        await InvokeAsync(middleware, context, next);

        Assert.Equal((int)HttpStatusCode.Unauthorized, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey(Codec.ServerPublicKeyHeader));
        Assert.False(context.Response.Headers.ContainsKey(Codec.NonceHeader));
        Assert.False(context.Response.Headers.ContainsKey(Codec.TagHeader));
        Assert.False(context.Response.Headers.ContainsKey(Codec.ProtocolVersionHeader));
    }

    private static byte[] ReadResponseBody(DefaultHttpContext context)
    {
        var stream = Assert.IsType<MemoryStream>(context.Response.Body);
        return stream.ToArray();
    }
}
