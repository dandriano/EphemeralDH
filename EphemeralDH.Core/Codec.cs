using System;
using System.Security.Cryptography;

namespace EphemeralDH.Core;

/// <summary>
/// Header codec for the handshake and one-operation session exchange.
/// </summary>
public static class Codec
{
    public const string ClientPublicKeyHeader = "X-EDHX-Client-Public-Key";
    public const string ServerPublicKeyHeader = "X-EDHX-Server-Public-Key";
    public const string SessionIdHeader = "X-EDHX-Session-Id";
    public const string ProtocolVersionHeader = "X-EDHX-Protocol-Version";
    public const string SessionPath = "/.edhx/session";

    public static void SetClientPublicKey(IHeaderWriter headers, ReadOnlySpan<byte> publicKey)
    {
        using var _ = Crypto.ImportPublicKey(publicKey);
        headers.RemoveHeader(ClientPublicKeyHeader);
        headers.SetHeader(ClientPublicKeyHeader, Convert.ToBase64String(publicKey));
        headers.SetHeader(ProtocolVersionHeader, Crypto.ProtocolVersion);
    }

    public static byte[] ReadClientPublicKey(IHeaderReader headers)
        => ReadPublicKey(headers, ClientPublicKeyHeader);

    public static void SetHandshakeResponse(IHeaderWriter headers, HandshakeResponse response)
    {
        response.Validate();
        headers.SetHeader(ServerPublicKeyHeader, Convert.ToBase64String(response.ServerPublicKey));
        headers.SetHeader(SessionIdHeader, response.SessionId);
        headers.SetHeader(ProtocolVersionHeader, response.ProtocolVersion);
    }

    public static HandshakeResponse ReadHandshakeResponse(IHeaderReader headers)
    {
        var result = new HandshakeResponse(ReadRequiredHeader(headers, SessionIdHeader),
            ReadPublicKey(headers, ServerPublicKeyHeader), ReadRequiredHeader(headers, ProtocolVersionHeader));
        result.Validate();
        return result;
    }

    public static string ReadSessionId(IHeaderReader headers)
    {
        var id = ReadRequiredHeader(headers, SessionIdHeader);
        if (!Guid.TryParseExact(id, "N", out _)) throw new CryptographicException("Invalid session identifier.");
        return id;
    }

    public static void SetSessionId(IHeaderWriter headers, string sessionId)
    {
        if (!Guid.TryParseExact(sessionId, "N", out _)) throw new CryptographicException("Invalid session identifier.");
        headers.RemoveHeader(SessionIdHeader);
        headers.SetHeader(SessionIdHeader, sessionId);
        headers.SetHeader(ProtocolVersionHeader, Crypto.ProtocolVersion);
    }

    private static byte[] ReadPublicKey(IHeaderReader headers, string name)
    {
        byte[] bytes;
        try { bytes = Convert.FromBase64String(ReadRequiredHeader(headers, name)); }
        catch (FormatException ex) { throw new CryptographicException($"Invalid base64 content for {name}.", ex); }
        using var _ = Crypto.ImportPublicKey(bytes);
        return bytes;
    }

    private static string ReadRequiredHeader(IHeaderReader headers, string name)
    {
        if (!headers.TryGetHeader(name, out var value) || string.IsNullOrWhiteSpace(value))
            throw new CryptographicException($"Missing required header {name}.");
        return value!;
    }
}
