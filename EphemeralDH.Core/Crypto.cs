using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace EphemeralDH.Core;

/// <summary>
/// Primitive operations used by the unauthenticated P-256 session protocol.
/// </summary>
public static class Crypto
{
    public const string ProtocolVersion = "edhx1";
    public const int P256PublicKeyLength = 65;
    public const int NonceLength = 12;
    public const int TagLength = 16;
    public const int HkdfSha256MaxLength = 255 * 32;

    public static ECDiffieHellman CreateEphemeralKey() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    public static byte[] DeriveSharedSecret(ECDiffieHellman privateKey, ECDiffieHellmanPublicKey publicKey)
        => privateKey.DeriveRawSecretAgreement(publicKey);

    public static byte[] DeriveSharedSecret(ECDiffieHellman privateKey, ReadOnlySpan<byte> encodedPublicKey)
    {
        using var peer = ImportPublicKey(encodedPublicKey);
        return DeriveSharedSecret(privateKey, peer.PublicKey);
    }

    public static ECDiffieHellman ImportPublicKey(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != P256PublicKeyLength || encoded[0] != 0x04)
            throw new CryptographicException("Expected uncompressed P-256 public key bytes.");
        try
        {
            var key = ECDiffieHellman.Create();
            try
            {
                key.ImportParameters(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = encoded.Slice(1, 32).ToArray(), Y = encoded.Slice(33, 32).ToArray() },
                });
                return key;
            }
            catch 
            { 
                key.Dispose();
                throw;
            }
        }
        catch (CryptographicException) { throw; }
        catch (Exception ex) { throw new CryptographicException("Invalid P-256 public key.", ex); }
    }

    public static byte[] EncodePublicKey(ECDiffieHellmanPublicKey publicKey)
    {
        var q = publicKey.ExportParameters().Q;
        if (q.X is not { Length: 32 } x || q.Y is not { Length: 32 } y)
            throw new CryptographicException("Expected a P-256 public key.");
        
        var result = new byte[P256PublicKeyLength];
        result[0] = 0x04;
        x.CopyTo(result, 1);
        y.CopyTo(result, 33);

        return result;
    }

    public static byte[] HkdfSha256(ReadOnlySpan<byte> inputKeyMaterial, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int length)
    {
        if (inputKeyMaterial.IsEmpty) throw new CryptographicException("HKDF input key material cannot be empty.");
        if (length < 1 || length > HkdfSha256MaxLength) throw new CryptographicException($"Expected HKDF output length between 1 and {HkdfSha256MaxLength} bytes.");
        
        Span<byte> zeroSalt = stackalloc byte[32];
        zeroSalt.Clear();
        var actualSalt = salt.IsEmpty ? zeroSalt : salt;
        var prk = HMACSHA256.HashData(actualSalt, inputKeyMaterial);
        var output = new byte[length];
        var previous = Array.Empty<byte>();
        var offset = 0;
        for (byte counter = 1; offset < length; counter++)
        {
            var blockInput = new byte[previous.Length + info.Length + 1];
            previous.CopyTo(blockInput, 0);
            info.CopyTo(blockInput.AsSpan(previous.Length));
            blockInput[^1] = counter;
            previous = HMACSHA256.HashData(prk, blockInput);
            var count = Math.Min(previous.Length, length - offset);
            previous.AsSpan(0, count).CopyTo(output.AsSpan(offset));
            offset += count;
            CryptographicOperations.ZeroMemory(blockInput);
        }

        CryptographicOperations.ZeroMemory(prk);
        CryptographicOperations.ZeroMemory(previous);

        return output;
    }

    internal static byte[] HashTranscript(params ReadOnlyMemory<byte>[] parts)
    {
        var writer = new ArrayBufferWriter<byte>();
        Span<byte> prefix = stackalloc byte[4];
        foreach (var part in parts)
        {
            BinaryPrimitives.WriteUInt32BigEndian(prefix, checked((uint)part.Length));
            var span = writer.GetSpan(4 + part.Length);
            prefix.CopyTo(span);
            part.Span.CopyTo(span[4..]);
            writer.Advance(4 + part.Length);
        }

        return SHA256.HashData(writer.WrittenSpan);
    }

    public static byte[] CreateRestRecordContext(string method, string fullPathAndQuery, string identity, string sessionId)
        => HashTranscript(Encoding.UTF8.GetBytes(ProtocolVersion), Encoding.UTF8.GetBytes(method),
            Encoding.UTF8.GetBytes(fullPathAndQuery), Encoding.UTF8.GetBytes(identity), Encoding.UTF8.GetBytes(sessionId));
}
