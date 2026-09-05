using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace EphemeralDH.Core;

public static class CryptoCore
{
    public const int P256PublicKeyLength = 65;
    public const int NonceLength = 12;
    public const int TagLength = 16;
    public const int Aes256KeyLength = 32;
    private const int HkdfSha256MaxLength = 255 * 32;
    public const string ProtocolVersion = "edhx1";

    public static ECDiffieHellman CreateEphemeralKey()
        => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    public static byte[] DeriveSharedSecret(ECDiffieHellman privateKey, ECDiffieHellmanPublicKey publicKey)
        => privateKey.DeriveKeyMaterial(publicKey);

    public static byte[] DeriveSharedSecret(ECDiffieHellman privateKey, ReadOnlySpan<byte> encodedPublicKey)
    {
        if (encodedPublicKey.Length != P256PublicKeyLength || encodedPublicKey[0] != 0x04)
        {
            throw new CryptographicException("Expected uncompressed P-256 public key bytes.");
        }

        var x = encodedPublicKey.Slice(1, 32).ToArray();
        var y = encodedPublicKey.Slice(33, 32).ToArray();

        using var ecdh = ECDiffieHellman.Create();
        ecdh.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = x,
                Y = y,
            },
        });

        return DeriveSharedSecret(privateKey, ecdh.PublicKey);
    }

    public static byte[] DeriveSessionKey(byte[] sharedSecret, byte[] salt, byte[] info, int keySizeBytes = Aes256KeyLength)
    {
        ValidateKeyLength(keySizeBytes);

        return HkdfSha256(sharedSecret, salt, info, keySizeBytes);
    }

    public static byte[] EncryptResponse(byte[] key, byte[] plaintext, byte[] nonce, byte[] associatedData, out byte[] tag)
    {
        ValidateNonce(nonce);
        ValidateKeyLength(key.Length);

        var ciphertext = new byte[plaintext.Length];
        tag = new byte[TagLength];

        using var aes = new AesGcm(key, TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        return ciphertext;
    }

    public static byte[] DecryptResponse(byte[] key, byte[] ciphertext, byte[] nonce, byte[] tag, byte[] associatedData)
    {
        ValidateNonce(nonce);
        ValidateTag(tag);
        ValidateKeyLength(key.Length);

        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, TagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

        return plaintext;
    }

    public static byte[] BuildAssociatedData(string protocolVersion, string method, string path, string identity)
    {
        return ComputeTranscriptHash(protocolVersion, method, path, identity);
    }

    public static byte[] ComputeTranscriptHash(params string[] parts)
    {
        var writer = new ArrayBufferWriter<byte>();
        Span<byte> lengthPrefix = stackalloc byte[4];

        foreach (var part in parts)
        {
            var bytes = Encoding.UTF8.GetBytes(part);
            BinaryPrimitives.WriteInt32BigEndian(lengthPrefix, bytes.Length);

            var span = writer.GetSpan(4 + bytes.Length);
            lengthPrefix.CopyTo(span);
            bytes.CopyTo(span[4..]);
            writer.Advance(4 + bytes.Length);
        }

        return SHA256.HashData(writer.WrittenSpan);
    }

    public static byte[] EncodePublicKey(ECDiffieHellmanPublicKey publicKey)
    {
        var parameters = publicKey.ExportParameters();
        if (parameters.Q.X is null || parameters.Q.Y is null)
        {
            throw new CryptographicException("Public key is missing coordinates.");
        }

        var encoded = new byte[P256PublicKeyLength];
        encoded[0] = 0x04;
        Buffer.BlockCopy(parameters.Q.X, 0, encoded, 1, parameters.Q.X.Length);
        Buffer.BlockCopy(parameters.Q.Y, 0, encoded, 1 + parameters.Q.X.Length, parameters.Q.Y.Length);

        return encoded;
    }

    public static ClientRequestEnvelope CreateClientRequest(string username, string password, byte[] clientEphemeralPublicKey)
        => new(username, password, clientEphemeralPublicKey);

    public static ServerResponseEnvelope CreateServerResponse(byte[] serverEphemeralPublicKey, byte[] nonce, byte[] tag, string protocolVersion)
        => new(serverEphemeralPublicKey, nonce, tag, protocolVersion);

    public static byte[] DeriveRequestSalt(string method, string path, string identity)
        => ComputeTranscriptHash(ProtocolVersion, method, path, identity);

    private static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
    {
        if (length < 0 || length > HkdfSha256MaxLength)
        {
            throw new CryptographicException($"Expected HKDF output length between 0 and {HkdfSha256MaxLength} bytes.");
        }

        using var hmac = new HMACSHA256(salt.Length == 0 ? new byte[32] : salt);
        var prk = hmac.ComputeHash(ikm);
        var result = new byte[length];
        var previous = Array.Empty<byte>();
        var offset = 0;
        var counter = 1;
        var counterBuffer = new byte[1];

        while (offset < length)
        {
            using var hmacExpand = new HMACSHA256(prk);
            hmacExpand.TransformBlock(previous, 0, previous.Length, null, 0);
            hmacExpand.TransformBlock(info, 0, info.Length, null, 0);
            counterBuffer[0] = (byte)counter;
            hmacExpand.TransformFinalBlock(counterBuffer, 0, 1);
            previous = hmacExpand.Hash ?? throw new CryptographicException("HKDF failed.");
            var toCopy = Math.Min(previous.Length, length - offset);
            Buffer.BlockCopy(previous, 0, result, offset, toCopy);
            offset += toCopy;
            counter++;
        }

        CryptographicOperations.ZeroMemory(prk);
        return result;
    }

    private static void ValidateKeyLength(int keyLength)
    {
        if (keyLength != Aes256KeyLength)
        {
            throw new CryptographicException($"Expected {Aes256KeyLength}-byte AES-256 key.");
        }
    }

    private static void ValidateNonce(byte[] nonce)
    {
        if (nonce.Length != NonceLength)
        {
            throw new CryptographicException($"Expected {NonceLength}-byte AES-GCM nonce.");
        }
    }

    private static void ValidateTag(byte[] tag)
    {
        if (tag.Length != TagLength)
        {
            throw new CryptographicException($"Expected {TagLength}-byte AES-GCM tag.");
        }
    }
}

public sealed record ClientRequestEnvelope(string Username, string Password, byte[] ClientEphemeralPublicKey)
{
    public void Validate()
    {
        if (ClientEphemeralPublicKey.Length != CryptoCore.P256PublicKeyLength)
        {
            throw new CryptographicException("Expected P-256 client public key bytes.");
        }
    }
}

public sealed record ServerResponseEnvelope(byte[] ServerEphemeralPublicKey, byte[] Nonce, byte[] Tag, string ProtocolVersion)
{
    public void Validate()
    {
        if (ServerEphemeralPublicKey.Length != CryptoCore.P256PublicKeyLength)
        {
            throw new CryptographicException("Expected P-256 server public key bytes.");
        }

        if (Nonce.Length != CryptoCore.NonceLength)
        {
            throw new CryptographicException("Expected AES-GCM nonce bytes.");
        }

        if (Tag.Length != CryptoCore.TagLength)
        {
            throw new CryptographicException("Expected AES-GCM tag bytes.");
        }

        if (ProtocolVersion != CryptoCore.ProtocolVersion)
        {
            throw new CryptographicException("Unexpected protocol version.");
        }
    }
}

