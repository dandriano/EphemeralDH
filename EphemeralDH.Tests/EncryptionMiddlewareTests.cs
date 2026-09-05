using System;
using System.Linq;
using System.Net;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
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

        using var clientKey = CryptoCore.CreateEphemeralKey();
        var clientPublicKey = CryptoCore.EncodePublicKey(clientKey.PublicKey);

        var middleware = new EdhxEncryptionMiddleware();
        var context = new DefaultHttpContext();
        MarkAsEdhxEncryptedEndpoint(context);
        context.Response.Body = new MemoryStream();
        context.Request.Method = "POST";
        context.Request.Path = path;

        context.Request.Headers["X-EDHX-Username"] = username;
        context.Request.Headers[ProtocolCodec.ClientPublicKeyHeader] = Convert.ToBase64String(clientPublicKey);

        // `next` writes the plaintext body and sets 2xx status.
        static Task next(HttpContext ctx)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            return ctx.Response.WriteAsync(plaintextText);
        }

        await InvokeAsync(middleware, context, next);

        Assert.Equal((int)HttpStatusCode.OK, context.Response.StatusCode);
        Assert.True(context.Response.Headers.ContainsKey(ProtocolCodec.ServerPublicKeyHeader));
        Assert.True(context.Response.Headers.ContainsKey(ProtocolCodec.NonceHeader));
        Assert.True(context.Response.Headers.ContainsKey(ProtocolCodec.TagHeader));
        Assert.True(context.Response.Headers.ContainsKey(ProtocolCodec.ProtocolVersionHeader));

        var cipherBytes = ReadResponseBody(context);
        Assert.False(plaintext.SequenceEqual(cipherBytes));

        var serverPublicKeyB64 = context.Response.Headers[ProtocolCodec.ServerPublicKeyHeader].ToString();
        var serverNonceB64 = context.Response.Headers[ProtocolCodec.NonceHeader].ToString();
        var tagB64 = context.Response.Headers[ProtocolCodec.TagHeader].ToString();
        var protocolVersion = context.Response.Headers[ProtocolCodec.ProtocolVersionHeader].ToString();

        var serverEphemeralPublicKey = Convert.FromBase64String(serverPublicKeyB64);
        var nonce = Convert.FromBase64String(serverNonceB64);
        var tag = Convert.FromBase64String(tagB64);

        Assert.Equal(CryptoCore.ProtocolVersion, protocolVersion);

        // Compute client side session key using server ephemeral public key.
        var sharedSecret = CryptoCore.DeriveSharedSecret(clientKey, serverEphemeralPublicKey);
        var requestSalt = CryptoCore.DeriveRequestSalt("POST", path, username);
        var info = Encoding.UTF8.GetBytes(path); // must match middleware
        var clientSessionKey = CryptoCore.DeriveSessionKey(sharedSecret, requestSalt, info);
        var aad = CryptoCore.BuildAssociatedData(CryptoCore.ProtocolVersion, "POST", path, username);

        var decrypted = CryptoCore.DecryptResponse(clientSessionKey, cipherBytes, nonce, tag, aad);
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
        using var key = CryptoCore.CreateEphemeralKey();
        var clientPublicKey = CryptoCore.EncodePublicKey(key.PublicKey);
        context.Request.Headers[ProtocolCodec.ClientPublicKeyHeader] = Convert.ToBase64String(clientPublicKey);

        static Task next(HttpContext ctx)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            return ctx.Response.WriteAsync("should-not-run");
        }

        await InvokeAsync(middleware, context, next);

        Assert.Equal((int)HttpStatusCode.Unauthorized, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey(ProtocolCodec.ServerPublicKeyHeader));
        Assert.False(context.Response.Headers.ContainsKey(ProtocolCodec.NonceHeader));
        Assert.False(context.Response.Headers.ContainsKey(ProtocolCodec.TagHeader));
        Assert.False(context.Response.Headers.ContainsKey(ProtocolCodec.ProtocolVersionHeader));
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

        context.Request.Headers["X-EDHX-Username"] = username;

        static Task next(HttpContext ctx)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            return ctx.Response.WriteAsync("should-not-run");
        }

        await InvokeAsync(middleware, context, next);

        Assert.Equal((int)HttpStatusCode.Unauthorized, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey(ProtocolCodec.ServerPublicKeyHeader));
        Assert.False(context.Response.Headers.ContainsKey(ProtocolCodec.NonceHeader));
        Assert.False(context.Response.Headers.ContainsKey(ProtocolCodec.TagHeader));
        Assert.False(context.Response.Headers.ContainsKey(ProtocolCodec.ProtocolVersionHeader));
    }

    private static byte[] ReadResponseBody(DefaultHttpContext context)
    {
        var stream = Assert.IsType<MemoryStream>(context.Response.Body);
        return stream.ToArray();
    }
}
