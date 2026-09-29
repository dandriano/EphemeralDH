using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using EphemeralDH.Core;

namespace EphemeralDH.Tests;

public class CryptoCoreTests
{
    private static (Session Client, Session Server) CreatePair()
    {
        using var handshake = new HandshakeRequest();
        var (response, server) = Handshake.CreateSession(handshake.PublicKey);
        return (handshake.Complete(response), server);
    }

    [Fact]
    public void RawEcdhSecret_IsSymmetric_AndPublicKeysAreValidated()
    {
        using var client = Crypto.CreateEphemeralKey();
        using var server = Crypto.CreateEphemeralKey();
        var left = Crypto.DeriveSharedSecret(client, server.PublicKey);
        var right = Crypto.DeriveSharedSecret(server, Crypto.EncodePublicKey(client.PublicKey));
        Assert.Equal(32, left.Length);
        Assert.Equal(left, right);
        Assert.Throws<CryptographicException>(() => Crypto.ImportPublicKey(new byte[65]));
    }

    [Fact]
    public void HkdfSha256_MatchesRfc5869CaseOne()
    {
        var ikm = Enumerable.Repeat((byte)0x0b, 22).ToArray();
        var salt = Convert.FromHexString("000102030405060708090a0b0c");
        var info = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9");
        var actual = Crypto.HkdfSha256(ikm, salt, info, 42);
        Assert.Equal(Convert.FromHexString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), actual);
        Assert.Throws<CryptographicException>(() => Crypto.HkdfSha256(ikm, salt, info, Crypto.HkdfSha256MaxLength + 1));
    }

    [Fact]
    public void Handshake_DirectionsAreSeparate_AndMessagesRoundTripBothWays()
    {
        var (client, server) = CreatePair();
        using (client)
        using (server)
        {
            var context = Encoding.UTF8.GetBytes("rest context");
            var request = client.EncryptMessage(Encoding.UTF8.GetBytes("request"), context);
            Assert.Equal("request", Encoding.UTF8.GetString(server.DecryptMessage(request, context)));
            var response = server.EncryptMessage(Encoding.UTF8.GetBytes("response"), context);
            Assert.Equal("response", Encoding.UTF8.GetString(client.DecryptMessage(response, context)));
        }
    }

    [Fact]
    public void RecordsRejectTamperingWrongContextReplayAndMissingClose()
    {
        var (client, server) = CreatePair();
        using (client) using (server)
        {
            var encoded = client.EncryptMessage(Encoding.UTF8.GetBytes("data"), "bound"u8);
            var tampered = encoded.ToArray(); tampered[13] ^= 0x40;
            Assert.Throws<AuthenticationTagMismatchException>(() => server.DecryptMessage(tampered, "bound"u8));
        }

        (client, server) = CreatePair();
        using (client) using (server)
        {
            var encoded = client.EncryptMessage(Encoding.UTF8.GetBytes("data"), "bound"u8);
            Assert.Throws<AuthenticationTagMismatchException>(() => server.DecryptMessage(encoded, "other"u8));
        }

        (client, server) = CreatePair();
        using (client) using (server)
        {
            var encoded = client.EncryptMessage(Encoding.UTF8.GetBytes("data"), "bound"u8);
            Assert.Throws<CryptographicException>(() => server.DecryptMessage(encoded.AsSpan(0, encoded.Length - 4), "bound"u8));
        }

        (client, server) = CreatePair();
        using (client) using (server)
        {
            var frame = client.EncryptRecord("data"u8, "bound"u8, close: false);
            var repeated = frame.Concat(frame).ToArray();
            Assert.Throws<CryptographicException>(() => server.DecryptMessage(repeated, "bound"u8));
        }
    }

    [Fact]
    public async Task CryptoStream_HandlesPartialAsyncReadsAndAuthenticatedClose()
    {
        var (client, server) = CreatePair();
        var plaintext = Enumerable.Range(0, 50_000).Select(i => (byte)(i % 251)).ToArray();
        await using var encoded = new MemoryStream();
        await using (var writer = new Core.CryptoStream(new FragmentedStream(encoded, maxRead: int.MaxValue), client, "stream"u8.ToArray(), leaveOpen: true))
        {
            await writer.WriteAsync(plaintext.AsMemory());
        }

        encoded.Position = 0;
        await using var reader = new Core.CryptoStream(new FragmentedStream(encoded, maxRead: 3), server, "stream"u8.ToArray(), leaveOpen: true);
        await using var decoded = new MemoryStream();
        await reader.CopyToAsync(decoded);
        Assert.Equal(plaintext, decoded.ToArray());
    }

    [Fact]
    public async Task CryptoStream_RejectsTruncatedInputBeforeClose()
    {
        var (client, server) = CreatePair();
        var record = client.EncryptRecord("payload"u8, ReadOnlySpan<byte>.Empty, close: false);
        var backing = new MemoryStream();
        backing.Write(record);
        backing.Position = 0;
        await using var source = new FragmentedStream(backing, maxRead: 2);
        await using var reader = new Core.CryptoStream(source, server, leaveOpen: true);
        var buffer = new byte[20];
        Assert.Equal(7, await reader.ReadAsync(buffer));
        await Assert.ThrowsAsync<CryptographicException>(async () => await reader.ReadAsync(buffer));
    }

    private sealed class FragmentedStream(Stream inner, int maxRead) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, Math.Min(count, maxRead));
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => inner.ReadAsync(buffer[..Math.Min(buffer.Length, maxRead)], cancellationToken);
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => inner.WriteAsync(buffer, cancellationToken);
        public override void Flush() => inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => inner.SetLength(value);
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
        public override ValueTask DisposeAsync() => inner.DisposeAsync();
    }
}
