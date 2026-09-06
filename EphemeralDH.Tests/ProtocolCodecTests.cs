using System;
using System.Security.Cryptography;
using EphemeralDH.Core;


namespace EphemeralDH.Tests;

public class ProtocolCodecTests
{
    private sealed class InMemoryHeaders : IHeaderReader, IHeaderWriter
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
        using var key = Crypto.CreateEphemeralKey();
        var encoded = Crypto.EncodePublicKey(key.PublicKey);

        Codec.SetClientPublicKey(headers, encoded);
        var decoded = Codec.ReadClientPublicKey(headers);

        Assert.True(MemoryExtensions.SequenceEqual<byte>(decoded, encoded));
    }

    [Fact]
    public void ServerResponseHeaders_RoundTrip()
    {
        var headers = new InMemoryHeaders();
        using var server = Crypto.CreateEphemeralKey();
        var serverEphemeralPublicKey = Crypto.EncodePublicKey(server.PublicKey);
        var nonce = RandomNumberGenerator.GetBytes(Crypto.NonceLength);
        var tag = RandomNumberGenerator.GetBytes(Crypto.TagLength);
        var response = new ServerResponseEnvelope(serverEphemeralPublicKey, nonce, tag, Crypto.ProtocolVersion);

        Codec.SetServerResponseHeaders(headers, response);
        var roundtripped = Codec.ReadServerResponseHeaders(headers);

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
            Codec.ReadServerResponseHeaders(headers));

        Assert.Contains("Missing required header", ex.Message);
    }
}
