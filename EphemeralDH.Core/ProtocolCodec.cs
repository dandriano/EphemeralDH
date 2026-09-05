using System;
using System.Security.Cryptography;

namespace EphemeralDH.Core;

public static class ProtocolCodec
{
    public const string ClientPublicKeyHeader = "X-EDHX-Client-Public-Key";
    public const string ServerPublicKeyHeader = "X-EDHX-Server-Public-Key";
    public const string NonceHeader = "X-EDHX-Nonce";
    public const string TagHeader = "X-EDHX-Tag";
    public const string ProtocolVersionHeader = "X-EDHX-Protocol-Version";

    public static void SetClientPublicKey(IProtocolHeaderWriter headers, byte[] clientPublicKey)
    {
        headers.RemoveHeader(ClientPublicKeyHeader);
        headers.SetHeader(ClientPublicKeyHeader, Convert.ToBase64String(clientPublicKey));
    }

    public static byte[] ReadClientPublicKey(IProtocolHeaderReader headers)
        => ReadRequiredBytes(headers, ClientPublicKeyHeader);

    public static void SetServerResponseHeaders(IProtocolHeaderWriter headers, ServerResponseEnvelope response)
    {
        response.Validate();
        headers.RemoveHeader(ServerPublicKeyHeader);
        headers.RemoveHeader(NonceHeader);
        headers.RemoveHeader(TagHeader);
        headers.RemoveHeader(ProtocolVersionHeader);

        headers.SetHeader(ServerPublicKeyHeader, Convert.ToBase64String(response.ServerEphemeralPublicKey));
        headers.SetHeader(NonceHeader, Convert.ToBase64String(response.Nonce));
        headers.SetHeader(TagHeader, Convert.ToBase64String(response.Tag));
        headers.SetHeader(ProtocolVersionHeader, response.ProtocolVersion);
    }

    public static ServerResponseEnvelope ReadServerResponseHeaders(IProtocolHeaderReader headers)
    {
        var serverPublicKey = ReadRequiredBytes(headers, ServerPublicKeyHeader);
        var nonce = ReadRequiredBytes(headers, NonceHeader);
        var tag = ReadRequiredBytes(headers, TagHeader);
        var protocolVersion = ReadRequiredHeader(headers, ProtocolVersionHeader);

        var response = new ServerResponseEnvelope(serverPublicKey, nonce, tag, protocolVersion);
        response.Validate();
        return response;
    }

    private static byte[] ReadRequiredBytes(IProtocolHeaderReader headers, string name)
    {
        var value = ReadRequiredHeader(headers, name);
        try
        {
            return Convert.FromBase64String(value);
        }
        catch (FormatException ex)
        {
            throw new CryptographicException($"Invalid base64 content for {name}.", ex);
        }
    }

    private static string ReadRequiredHeader(IProtocolHeaderReader headers, string name)
    {
        if (!headers.TryGetHeader(name, out var value) || string.IsNullOrWhiteSpace(value))
        {
            throw new CryptographicException($"Missing required header {name}.");
        }

        return value!;
    }
}

