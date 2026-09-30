using System;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using EphemeralDH.Core;
using EphemeralDH.Middleware;
using Microsoft.AspNetCore.Http;

namespace EphemeralDH.Tests;

public class EncryptionMiddlewareTests
{
    private const string Username = "alice";

    private static void MarkAsEncrypted(DefaultHttpContext context)
    {
        var metadataType = typeof(CryptoMiddleware).Assembly.GetType("EphemeralDH.Middleware.EncryptionRequiredMetadata", true)!;
        var metadata = Activator.CreateInstance(metadataType)!;
        context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection([metadata]), "secure"));
    }

    private static DefaultHttpContext CreateAuthenticatedContext(string path)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, Username)], "test"));
        context.Response.Body = new MemoryStream();
        return context;
    }

    [Fact]
    public async Task HandshakeThenProtectedRequestAndErrorResponseAreBothEncrypted_AndSessionIsOneUse()
    {
        using var clientHandshake = new HandshakeRequest();
        using var store = new InMemorySessionStore();
        var middleware = new CryptoMiddleware(store);

        var handshakeContext = CreateAuthenticatedContext(Codec.SessionPath);
        handshakeContext.Request.Method = HttpMethods.Post;
        handshakeContext.Request.Headers[Codec.ClientPublicKeyHeader] = Convert.ToBase64String(clientHandshake.PublicKey);
        handshakeContext.Request.Headers[Codec.ProtocolVersionHeader] = Crypto.ProtocolVersion;
        await middleware.InvokeAsync(handshakeContext, _ => throw new InvalidOperationException("Handshake must terminate in middleware."));

        Assert.Equal(StatusCodes.Status204NoContent, handshakeContext.Response.StatusCode);
        var sessionId = handshakeContext.Response.Headers[Codec.SessionIdHeader].ToString();
        var handshakeResponse = new HandshakeResponse(sessionId,
            Convert.FromBase64String(handshakeContext.Response.Headers[Codec.ServerPublicKeyHeader].ToString()),
            handshakeContext.Response.Headers[Codec.ProtocolVersionHeader].ToString());
        using var clientSession = clientHandshake.Complete(handshakeResponse);

        const string path = "/api/secure?mode=error";
        var contextBinding = Crypto.CreateRestRecordContext("POST", path, sessionId);
        var requestPlaintext = Encoding.UTF8.GetBytes("request secret");
        var protectedRequest = clientSession.EncryptMessage(requestPlaintext, contextBinding);
        var request = CreateAuthenticatedContext("/api/secure");
        request.Request.Method = HttpMethods.Post;
        request.Request.QueryString = new QueryString("?mode=error");
        request.Request.Headers[Codec.SessionIdHeader] = sessionId;
        request.Request.Headers[Codec.ProtocolVersionHeader] = Crypto.ProtocolVersion;
        request.Request.Body = new MemoryStream(protectedRequest);
        MarkAsEncrypted(request);

        await middleware.InvokeAsync(request, async ctx =>
        {
            using var body = new MemoryStream();
            await ctx.Request.Body.CopyToAsync(body);
            Assert.Equal(requestPlaintext, body.ToArray());
            ctx.Response.StatusCode = StatusCodes.Status422UnprocessableEntity;
            await ctx.Response.WriteAsync("encrypted error details");
        });

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, request.Response.StatusCode);
        Assert.Equal(Crypto.ProtocolVersion, request.Response.Headers[Codec.ProtocolVersionHeader]);
        request.Response.Body.Position = 0;
        using var protectedResponse = new MemoryStream();
        await request.Response.Body.CopyToAsync(protectedResponse);
        Assert.Equal("encrypted error details", Encoding.UTF8.GetString(clientSession.DecryptMessage(protectedResponse.ToArray(), contextBinding)));

        var replay = CreateAuthenticatedContext("/api/secure");
        replay.Request.Method = HttpMethods.Post;
        replay.Request.QueryString = new QueryString("?mode=error");
        replay.Request.Headers[Codec.SessionIdHeader] = sessionId;
        replay.Request.Headers[Codec.ProtocolVersionHeader] = Crypto.ProtocolVersion;
        replay.Request.Body = new MemoryStream(protectedRequest);
        MarkAsEncrypted(replay);
        await middleware.InvokeAsync(replay, _ => throw new InvalidOperationException("Replayed session must be rejected."));
        Assert.Equal(StatusCodes.Status400BadRequest, replay.Response.StatusCode);
    }

    [Fact]
    public void SessionStore_ExpiresAndConsumesEachSessionOnce()
    {
        using var clientHandshake = new HandshakeRequest();
        var (expiredResponse, expiredSession) = Handshake.CreateSession(clientHandshake.PublicKey);
        using var store = new InMemorySessionStore();
        store.Add(expiredResponse.SessionId, expiredSession, DateTimeOffset.UtcNow.AddSeconds(1));
        Assert.False(store.TryTake(expiredResponse.SessionId, DateTimeOffset.UtcNow.AddSeconds(2), out _));

        var (response, session) = Handshake.CreateSession(clientHandshake.PublicKey);
        store.Add(response.SessionId, session, DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.True(store.TryTake(response.SessionId, DateTimeOffset.UtcNow, out var taken));
        Assert.NotNull(taken);
        taken!.Dispose();
        Assert.False(store.TryTake(response.SessionId, DateTimeOffset.UtcNow, out _));
    }

    [Fact]
    public async Task MalformedRestRecordReturnsBadRequestAndConsumesSession()
    {
        using var clientHandshake = new HandshakeRequest();
        using var store = new InMemorySessionStore();
        var middleware = new CryptoMiddleware(store);
        var handshakeContext = CreateAuthenticatedContext(Codec.SessionPath);
        handshakeContext.Request.Method = HttpMethods.Post;
        handshakeContext.Request.Headers[Codec.ClientPublicKeyHeader] = Convert.ToBase64String(clientHandshake.PublicKey);
        handshakeContext.Request.Headers[Codec.ProtocolVersionHeader] = Crypto.ProtocolVersion;
        await middleware.InvokeAsync(handshakeContext, _ => throw new InvalidOperationException());

        var id = handshakeContext.Response.Headers[Codec.SessionIdHeader].ToString();
        var response = new HandshakeResponse(id,
            Convert.FromBase64String(handshakeContext.Response.Headers[Codec.ServerPublicKeyHeader].ToString()),
            Crypto.ProtocolVersion);
        using var client = clientHandshake.Complete(response);
        var binding = Crypto.CreateRestRecordContext("POST", "/api/secure", id);
        var body = client.EncryptMessage("secret"u8.ToArray(), binding);
        body[13] ^= 1;

        var request = CreateAuthenticatedContext("/api/secure");
        request.Request.Method = HttpMethods.Post;
        request.Request.Headers[Codec.SessionIdHeader] = id;
        request.Request.Headers[Codec.ProtocolVersionHeader] = Crypto.ProtocolVersion;
        request.Request.Body = new MemoryStream(body);
        MarkAsEncrypted(request);
        await middleware.InvokeAsync(request, _ => throw new InvalidOperationException("Malformed records must not reach the endpoint."));
        Assert.Equal(StatusCodes.Status400BadRequest, request.Response.StatusCode);
    }
}
