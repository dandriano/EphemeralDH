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
        using var client = Crypto.CreateEphemeralKey();
        using var server = Crypto.CreateEphemeralKey();

        var clientSecret = Crypto.DeriveSharedSecret(client, server.PublicKey);
        var serverSecret = Crypto.DeriveSharedSecret(server, client.PublicKey);

        Assert.True(MemoryExtensions.SequenceEqual<byte>(clientSecret, serverSecret));
    }

    [Fact]
    public void ProtocolRoundtrip_EncryptsBodyAndDecryptsWithReturnedHeaders()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret message");
        using var client = Crypto.CreateEphemeralKey();
        using var server = Crypto.CreateEphemeralKey();

        var clientPublicKey = Crypto.EncodePublicKey(client.PublicKey);
        var request = Crypto.CreateClientRequest("alice", clientPublicKey);
        request.Validate();

        var requestSalt = Crypto.DeriveRequestSalt("POST", "/api/secure", request.Username);
        var clientSharedSecret = Crypto.DeriveSharedSecret(client, server.PublicKey);
        var clientSessionKey = Crypto.DeriveSessionKey(clientSharedSecret, requestSalt, Encoding.UTF8.GetBytes("response-body"));

        var nonce = RandomNumberGenerator.GetBytes(Crypto.NonceLength);
        var aad = Crypto.BuildAssociatedData(Crypto.ProtocolVersion, "POST", "/api/secure", request.Username);
        var ciphertext = Crypto.EncryptResponse(clientSessionKey, plaintext, nonce, aad, out var tag);

        var response = Crypto.CreateServerResponse(Crypto.EncodePublicKey(server.PublicKey), nonce, tag, Crypto.ProtocolVersion);
        response.Validate();

        var serverSharedSecret = Crypto.DeriveSharedSecret(server, clientPublicKey);
        var serverSessionKey = Crypto.DeriveSessionKey(serverSharedSecret, requestSalt, Encoding.UTF8.GetBytes("response-body"));
        var decrypted = Crypto.DecryptResponse(serverSessionKey, ciphertext, response.Nonce, response.Tag, aad);

        Assert.True(MemoryExtensions.SequenceEqual<byte>(decrypted, plaintext));
    }

    [Fact]
    public void AadMismatch_ChangingMetadataBreaksDecryption()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret message");
        using var client = Crypto.CreateEphemeralKey();
        using var server = Crypto.CreateEphemeralKey();

        var sharedSecret = Crypto.DeriveSharedSecret(client, server.PublicKey);
        var key = Crypto.DeriveSessionKey(sharedSecret, Crypto.DeriveRequestSalt("POST", "/api/secure", "alice"), Encoding.UTF8.GetBytes("response-body"));
        var nonce = RandomNumberGenerator.GetBytes(Crypto.NonceLength);

        var aad = Crypto.BuildAssociatedData(Crypto.ProtocolVersion, "POST", "/api/secure", "alice");
        var ciphertext = Crypto.EncryptResponse(key, plaintext, nonce, aad, out var tag);

        var badAad = Crypto.BuildAssociatedData("dhx2", "POST", "/api/secure", "alice");

        Assert.Throws<AuthenticationTagMismatchException>(() => Crypto.DecryptResponse(key, ciphertext, nonce, tag, badAad));
    }

    [Fact]
    public void TamperedCiphertext_Throws()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret message");
        using var client = Crypto.CreateEphemeralKey();
        using var server = Crypto.CreateEphemeralKey();

        var sharedSecret = Crypto.DeriveSharedSecret(client, server.PublicKey);
        var key = Crypto.DeriveSessionKey(sharedSecret, Crypto.DeriveRequestSalt("POST", "/api/secure", "alice"), Encoding.UTF8.GetBytes("response-body"));
        var nonce = RandomNumberGenerator.GetBytes(Crypto.NonceLength);
        var aad = Crypto.BuildAssociatedData(Crypto.ProtocolVersion, "POST", "/api/secure", "alice");

        var ciphertext = Crypto.EncryptResponse(key, plaintext, nonce, aad, out var tag);
        ciphertext[0] ^= 0x01;

        Assert.Throws<AuthenticationTagMismatchException>(() => Crypto.DecryptResponse(key, ciphertext, nonce, tag, aad));
    }

    [Fact]
    public void TamperedTag_Throws()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret message");
        using var client = Crypto.CreateEphemeralKey();
        using var server = Crypto.CreateEphemeralKey();

        var sharedSecret = Crypto.DeriveSharedSecret(client, server.PublicKey);
        var key = Crypto.DeriveSessionKey(sharedSecret, Crypto.DeriveRequestSalt("POST", "/api/secure", "alice"), Encoding.UTF8.GetBytes("response-body"));
        var nonce = RandomNumberGenerator.GetBytes(Crypto.NonceLength);
        var aad = Crypto.BuildAssociatedData(Crypto.ProtocolVersion, "POST", "/api/secure", "alice");

        var ciphertext = Crypto.EncryptResponse(key, plaintext, nonce, aad, out var tag);
        tag[0] ^= 0x01;

        Assert.Throws<AuthenticationTagMismatchException>(() => Crypto.DecryptResponse(key, ciphertext, nonce, tag, aad));
    }

    [Fact]
    public void TamperedNonce_Throws()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret message");
        using var client = Crypto.CreateEphemeralKey();
        using var server = Crypto.CreateEphemeralKey();

        var sharedSecret = Crypto.DeriveSharedSecret(client, server.PublicKey);
        var key = Crypto.DeriveSessionKey(sharedSecret, Crypto.DeriveRequestSalt("POST", "/api/secure", "alice"), Encoding.UTF8.GetBytes("response-body"));
        var nonce = RandomNumberGenerator.GetBytes(Crypto.NonceLength);
        var aad = Crypto.BuildAssociatedData(Crypto.ProtocolVersion, "POST", "/api/secure", "alice");

        var ciphertext = Crypto.EncryptResponse(key, plaintext, nonce, aad, out var tag);
        nonce[0] ^= 0x01;

        Assert.Throws<AuthenticationTagMismatchException>(() => Crypto.DecryptResponse(key, ciphertext, nonce, tag, aad));
    }
}
