using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using EphemeralDH.Core;

namespace EphemeralDH.Tests;

public class ProtocolCodecTests
{
    private sealed class InMemoryHeaders : IHeaderReader, IHeaderWriter
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);
        public bool TryGetHeader(string name, out string? value) => _values.TryGetValue(name, out value);
        public void SetHeader(string name, string value) => _values[name] = value;
        public void RemoveHeader(string name) => _values.Remove(name);
    }

    [Fact]
    public void RestHandshakeHeaders_RoundTripAndValidateP256Key()
    {
        var headers = new InMemoryHeaders();
        using var client = new HandshakeRequest();
        var (response, server) = Handshake.CreateSession(client.PublicKey);
        using (server)
        {
            Codec.SetHandshakeResponse(headers, response);
            var decoded = Codec.ReadHandshakeResponse(headers);
            Assert.Equal(response.SessionId, decoded.SessionId);
            Assert.Equal(Crypto.ProtocolVersion, decoded.ProtocolVersion);
            Assert.Equal(response.ServerPublicKey, decoded.ServerPublicKey);
            using var session = client.Complete(decoded);
        }
    }

    [Fact]
    public void MissingOrMalformedHandshakeHeadersFailClosed()
    {
        var headers = new InMemoryHeaders();
        Assert.Throws<CryptographicException>(() => Codec.ReadHandshakeResponse(headers));
        headers.SetHeader(Codec.SessionIdHeader, Guid.NewGuid().ToString("N"));
        headers.SetHeader(Codec.ServerPublicKeyHeader, Convert.ToBase64String(new byte[65]));
        headers.SetHeader(Codec.ProtocolVersionHeader, "edhx1");
        Assert.Throws<CryptographicException>(() => Codec.ReadHandshakeResponse(headers));
    }
}
