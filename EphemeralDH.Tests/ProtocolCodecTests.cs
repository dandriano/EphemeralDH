using System;
using System.Security.Cryptography;
using EphemeralDH.Core;


namespace EphemeralDH.Tests;

public class ProtocolCodecTests
{
    private sealed class InMemoryHeaders : IProtocolHeaderReader, IProtocolHeaderWriter
    {
        private readonly System.Collections.Generic.Dictionary<string, string> _values =
            new(StringComparer.OrdinalIgnoreCase);

        public bool TryGetHeader(string name, out string? value)
        {
            if (_values.TryGetValue(name, out var existing) && !string.IsNullOrWhiteSpace(existing))
            {
                value = existing;
                return true;
            }

            value = null;
            return false;
        }

        public void SetHeader(string name, string value)
            => _values[name] = value;

        public void RemoveHeader(string name)
            => _values.Remove(name);
    }

    [Fact]
    public void ClientPublicKeyHeader_RoundTrip()
    {
        var headers = new InMemoryHeaders();
        using var key = CryptoCore.CreateEphemeralKey();
        var encoded = CryptoCore.EncodePublicKey(key.PublicKey);

        ProtocolCodec.SetClientPublicKey(headers, encoded);
        var decoded = ProtocolCodec.ReadClientPublicKey(headers);

        Assert.True(MemoryExtensions.SequenceEqual<byte>(decoded, encoded));
    }

    [Fact]
    public void ServerResponseHeaders_RoundTrip()
    {
        var headers = new InMemoryHeaders();
        using var server = CryptoCore.CreateEphemeralKey();
        var serverEphemeralPublicKey = CryptoCore.EncodePublicKey(server.PublicKey);
        var nonce = RandomNumberGenerator.GetBytes(CryptoCore.NonceLength);
        var tag = RandomNumberGenerator.GetBytes(CryptoCore.TagLength);
        var response = new ServerResponseEnvelope(serverEphemeralPublicKey, nonce, tag, CryptoCore.ProtocolVersion);

        ProtocolCodec.SetServerResponseHeaders(headers, response);
        var roundtripped = ProtocolCodec.ReadServerResponseHeaders(headers);

        Assert.True(MemoryExtensions.SequenceEqual<byte>(roundtripped.ServerEphemeralPublicKey, response.ServerEphemeralPublicKey));
        Assert.True(MemoryExtensions.SequenceEqual<byte>(roundtripped.Nonce, response.Nonce));
        Assert.True(MemoryExtensions.SequenceEqual<byte>(roundtripped.Tag, response.Tag));
        Assert.True(response.ProtocolVersion == roundtripped.ProtocolVersion);
    }

    [Fact]
    public void MissingRequiredHeader_ThrowsCryptographicException()
    {
        var headers = new InMemoryHeaders();

        var ex = Assert.Throws<CryptographicException>(() =>
            ProtocolCodec.ReadServerResponseHeaders(headers));

        Assert.Contains("Missing required header", ex.Message);
    }
}
