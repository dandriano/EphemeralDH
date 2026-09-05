using System;
using System.Security.Cryptography;
using System.Text;
using EphemeralDH.Core;

namespace EphemeralDH.Tests;

public class CryptoCoreTests
{
    [Fact]
    public void SharedSecret_Symmetry_ClientMatchesServer()
    {
        using var client = CryptoCore.CreateEphemeralKey();
        using var server = CryptoCore.CreateEphemeralKey();

        var clientSecret = CryptoCore.DeriveSharedSecret(client, server.PublicKey);
        var serverSecret = CryptoCore.DeriveSharedSecret(server, client.PublicKey);

        Assert.True(MemoryExtensions.SequenceEqual<byte>(clientSecret, serverSecret));
    }

    [Fact]
    public void ProtocolRoundtrip_EncryptsBodyAndDecryptsWithReturnedHeaders()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret message");
        using var client = CryptoCore.CreateEphemeralKey();
        using var server = CryptoCore.CreateEphemeralKey();

        var clientPublicKey = CryptoCore.EncodePublicKey(client.PublicKey);
        var request = CryptoCore.CreateClientRequest("alice", "password", clientPublicKey);
        request.Validate();

        var requestSalt = CryptoCore.DeriveRequestSalt("POST", "/api/secure", request.Username);
        var clientSharedSecret = CryptoCore.DeriveSharedSecret(client, server.PublicKey);
        var clientSessionKey = CryptoCore.DeriveSessionKey(clientSharedSecret, requestSalt, Encoding.UTF8.GetBytes("response-body"));

        var nonce = RandomNumberGenerator.GetBytes(CryptoCore.NonceLength);
        var aad = CryptoCore.BuildAssociatedData(CryptoCore.ProtocolVersion, "POST", "/api/secure", request.Username);
        var ciphertext = CryptoCore.EncryptResponse(clientSessionKey, plaintext, nonce, aad, out var tag);

        var response = CryptoCore.CreateServerResponse(CryptoCore.EncodePublicKey(server.PublicKey), nonce, tag, CryptoCore.ProtocolVersion);
        response.Validate();

        var serverSharedSecret = CryptoCore.DeriveSharedSecret(server, clientPublicKey);
        var serverSessionKey = CryptoCore.DeriveSessionKey(serverSharedSecret, requestSalt, Encoding.UTF8.GetBytes("response-body"));
        var decrypted = CryptoCore.DecryptResponse(serverSessionKey, ciphertext, response.Nonce, response.Tag, aad);

        Assert.True(MemoryExtensions.SequenceEqual<byte>(decrypted, plaintext));
    }

    [Fact]
    public void AadMismatch_ChangingMetadataBreaksDecryption()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret message");
        using var client = CryptoCore.CreateEphemeralKey();
        using var server = CryptoCore.CreateEphemeralKey();

        var sharedSecret = CryptoCore.DeriveSharedSecret(client, server.PublicKey);
        var key = CryptoCore.DeriveSessionKey(sharedSecret, CryptoCore.DeriveRequestSalt("POST", "/api/secure", "alice"), Encoding.UTF8.GetBytes("response-body"));
        var nonce = RandomNumberGenerator.GetBytes(CryptoCore.NonceLength);

        var aad = CryptoCore.BuildAssociatedData(CryptoCore.ProtocolVersion, "POST", "/api/secure", "alice");
        var ciphertext = CryptoCore.EncryptResponse(key, plaintext, nonce, aad, out var tag);

        var badAad = CryptoCore.BuildAssociatedData("dhx2", "POST", "/api/secure", "alice");

        Assert.Throws<AuthenticationTagMismatchException>(() => CryptoCore.DecryptResponse(key, ciphertext, nonce, tag, badAad));
    }

    [Fact]
    public void TamperedCiphertext_Throws()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret message");
        using var client = CryptoCore.CreateEphemeralKey();
        using var server = CryptoCore.CreateEphemeralKey();

        var sharedSecret = CryptoCore.DeriveSharedSecret(client, server.PublicKey);
        var key = CryptoCore.DeriveSessionKey(sharedSecret, CryptoCore.DeriveRequestSalt("POST", "/api/secure", "alice"), Encoding.UTF8.GetBytes("response-body"));
        var nonce = RandomNumberGenerator.GetBytes(CryptoCore.NonceLength);
        var aad = CryptoCore.BuildAssociatedData(CryptoCore.ProtocolVersion, "POST", "/api/secure", "alice");

        var ciphertext = CryptoCore.EncryptResponse(key, plaintext, nonce, aad, out var tag);
        ciphertext[0] ^= 0x01;

        Assert.Throws<AuthenticationTagMismatchException>(() => CryptoCore.DecryptResponse(key, ciphertext, nonce, tag, aad));
    }

    [Fact]
    public void TamperedTag_Throws()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret message");
        using var client = CryptoCore.CreateEphemeralKey();
        using var server = CryptoCore.CreateEphemeralKey();

        var sharedSecret = CryptoCore.DeriveSharedSecret(client, server.PublicKey);
        var key = CryptoCore.DeriveSessionKey(sharedSecret, CryptoCore.DeriveRequestSalt("POST", "/api/secure", "alice"), Encoding.UTF8.GetBytes("response-body"));
        var nonce = RandomNumberGenerator.GetBytes(CryptoCore.NonceLength);
        var aad = CryptoCore.BuildAssociatedData(CryptoCore.ProtocolVersion, "POST", "/api/secure", "alice");

        var ciphertext = CryptoCore.EncryptResponse(key, plaintext, nonce, aad, out var tag);
        tag[0] ^= 0x01;

        Assert.Throws<AuthenticationTagMismatchException>(() => CryptoCore.DecryptResponse(key, ciphertext, nonce, tag, aad));
    }

    [Fact]
    public void TamperedNonce_Throws()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret message");
        using var client = CryptoCore.CreateEphemeralKey();
        using var server = CryptoCore.CreateEphemeralKey();

        var sharedSecret = CryptoCore.DeriveSharedSecret(client, server.PublicKey);
        var key = CryptoCore.DeriveSessionKey(sharedSecret, CryptoCore.DeriveRequestSalt("POST", "/api/secure", "alice"), Encoding.UTF8.GetBytes("response-body"));
        var nonce = RandomNumberGenerator.GetBytes(CryptoCore.NonceLength);
        var aad = CryptoCore.BuildAssociatedData(CryptoCore.ProtocolVersion, "POST", "/api/secure", "alice");

        var ciphertext = CryptoCore.EncryptResponse(key, plaintext, nonce, aad, out var tag);
        nonce[0] ^= 0x01;

        Assert.Throws<AuthenticationTagMismatchException>(() => CryptoCore.DecryptResponse(key, ciphertext, nonce, tag, aad));
    }
}
