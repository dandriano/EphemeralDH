using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using EphemeralDH.Core;
using EphemeralDH.Middleware.Headers;
using Microsoft.AspNetCore.Http;

namespace EphemeralDH.Middleware;

public sealed class CryptoMiddleware : IMiddleware
{
    private static readonly TimeSpan _ttl = TimeSpan.FromMinutes(1);
    private readonly ISessionStore _sessions;

    public CryptoMiddleware(ISessionStore sessions)
    {
        _sessions = sessions;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        if (IsHandshake(context))
        {
            await HandleHandshakeAsync(context);
            return;
        }

        if (context.GetEndpoint()?.Metadata.Any(m => m is EncryptionRequiredMetadata) != true)
        {
            await next(context);
            return;
        }

        var requestHeaders = new HttpRequestHeadersAdapter(context.Request);
        Session? session = null;
        string sessionId;
        byte[] requestPlaintext;
        byte[] recordContext;
        try
        {
            sessionId = Codec.ReadSessionId(requestHeaders);
            if (!requestHeaders.TryGetHeader(Codec.ProtocolVersionHeader, out var version) || version != Crypto.ProtocolVersion)
                throw new CryptographicException("Unexpected protocol version.");
            if (!_sessions.TryTake(sessionId, DateTimeOffset.UtcNow, out var taken) || taken is null)
                throw new CryptographicException("Unknown, expired, or already-used session.");
            session = taken;
            var fullPath = context.Request.PathBase + context.Request.Path + context.Request.QueryString;
            recordContext = Crypto.CreateRestRecordContext(context.Request.Method, fullPath, sessionId);
            using var encryptedBody = new MemoryStream();
            await context.Request.Body.CopyToAsync(encryptedBody, context.RequestAborted);
            requestPlaintext = session.DecryptMessage(encryptedBody.ToArray(), recordContext);
        }
        catch (CryptographicException)
        {
            session?.Dispose();
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        catch
        {
            session?.Dispose();
            throw;
        }

        var originalRequestBody = context.Request.Body;
        var originalResponseBody = context.Response.Body;
        await using var decryptedBody = new MemoryStream(requestPlaintext, writable: false);
        await using var encryptedResponse = new MemoryStream();
        context.Request.Body = decryptedBody;
        context.Request.ContentLength = requestPlaintext.Length;
        context.Response.Body = encryptedResponse;
        try
        {
            await next(context);
        }
        catch
        {
            session!.Dispose();
            throw;
        }
        finally
        {
            context.Request.Body = originalRequestBody;
            context.Response.Body = originalResponseBody;
        }

        try
        {
            var protectedResponse = session!.EncryptMessage(encryptedResponse.ToArray(), recordContext);
            context.Response.Headers.Remove("Content-Length");
            context.Response.ContentType = "application/octet-stream";
            context.Response.ContentLength = protectedResponse.Length;
            context.Response.Headers[Codec.ProtocolVersionHeader] = Crypto.ProtocolVersion;
            await originalResponseBody.WriteAsync(protectedResponse, context.RequestAborted);
        }
        finally { session!.Dispose(); }
    }

    private Task HandleHandshakeAsync(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method) || context.Request.QueryString.HasValue)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return Task.CompletedTask;
        }

        try
        {
            var headers = new HttpRequestHeadersAdapter(context.Request);
            if (!headers.TryGetHeader(Codec.ProtocolVersionHeader, out var version) || version != Crypto.ProtocolVersion)
                throw new CryptographicException("Unexpected protocol version.");
            var clientPublicKey = Codec.ReadClientPublicKey(headers);
            var (response, session) = Handshake.CreateSession(clientPublicKey);
            _sessions.Add(response.SessionId, session, DateTimeOffset.UtcNow + _ttl);
            Codec.SetHandshakeResponse(new HttpResponseHeadersAdapter(context.Response), response);
            context.Response.StatusCode = StatusCodes.Status204NoContent;
            return Task.CompletedTask;
        }
        catch (CryptographicException)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return Task.CompletedTask;
        }
    }

    private static bool IsHandshake(HttpContext context)
        => string.Equals(context.Request.Path.Value, Codec.SessionPath, StringComparison.Ordinal);
}
