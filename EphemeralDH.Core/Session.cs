using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace EphemeralDH.Core;

public enum Role 
{ 
    Client,
    Server
}

public sealed record HandshakeResponse(string SessionId, byte[] ServerPublicKey, string ProtocolVersion)
{
    public void Validate()
    {
        if (ProtocolVersion != Crypto.ProtocolVersion) throw new CryptographicException("Unexpected protocol version.");
        if (!Guid.TryParseExact(SessionId, "N", out _)) throw new CryptographicException("Invalid session identifier.");
        using var importedKey = Crypto.ImportPublicKey(ServerPublicKey);
    }
}

public sealed class HandshakeRequest : IDisposable
{
    private readonly ECDiffieHellman _privateKey = Crypto.CreateEphemeralKey();
    private bool _completed;
    public byte[] PublicKey { get; }

    public HandshakeRequest() 
    {
        PublicKey = Crypto.EncodePublicKey(_privateKey.PublicKey);
    }

    public Session Complete(HandshakeResponse response)
    {
        if (_completed) 
            throw new InvalidOperationException("Handshake has already been completed.");

        response.Validate();
        _completed = true;
        var secret = Crypto.DeriveSharedSecret(_privateKey, response.ServerPublicKey);

        try 
        { 
            return Session.Create(secret, PublicKey, response.ServerPublicKey, response.SessionId, Role.Client);
        }
        finally 
        { 
            CryptographicOperations.ZeroMemory(secret); 
        }
    }

    public void Dispose() => _privateKey.Dispose();
}

public static class Handshake
{
    public static (HandshakeResponse Response, Session Session) CreateSession(ReadOnlySpan<byte> clientPublicKey)
    {
        using var client = Crypto.ImportPublicKey(clientPublicKey);
        using var server = Crypto.CreateEphemeralKey();
        var serverPublic = Crypto.EncodePublicKey(server.PublicKey);
        var clientPublic = clientPublicKey.ToArray();
        var id = Guid.NewGuid().ToString("N");
        var secret = Crypto.DeriveSharedSecret(server, client.PublicKey);
        try
        {
            var session = Session.Create(secret, clientPublic, serverPublic, id, Role.Server);
            return (new HandshakeResponse(id, serverPublic, Crypto.ProtocolVersion), session);
        }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }
}


public sealed class Session : IDisposable
{
    public const int MaxRecordPayloadLength = 16 * 1024;
    internal const int RecordHeaderLength = 9;
    internal const int RecordOverhead = RecordHeaderLength + Crypto.TagLength + 4;
    private readonly byte[] _sendKey, _receiveKey, _sendNonceBase, _receiveNonceBase, _sessionId;
    private ulong _sendSequence, _receiveSequence;
    private bool _sendClosed, _receiveClosed, _disposed;

    public string SessionId { get; }
    public Role Role { get; }

    private Session(byte[] sendKey, byte[] receiveKey, byte[] sendNonceBase, byte[] receiveNonceBase, byte[] sessionId, string sessionIdText, Role role)
    {
        _sendKey = sendKey; _receiveKey = receiveKey;
        _sendNonceBase = sendNonceBase; _receiveNonceBase = receiveNonceBase;
        _sessionId = sessionId; SessionId = sessionIdText; Role = role;
    }

    internal static Session Create(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> clientPublic, ReadOnlySpan<byte> serverPublic, string sessionId, Role role)
    {
        if (!Guid.TryParseExact(sessionId, "N", out var id)) 
            throw new CryptographicException("Invalid session identifier.");

        var sessionBytes = id.ToByteArray();
        var version = Encoding.UTF8.GetBytes(Crypto.ProtocolVersion);
        var salt = Crypto.HashTranscript(version, clientPublic.ToArray(), serverPublic.ToArray(), sessionBytes);
        var info = Encoding.UTF8.GetBytes("directional traffic keys");
        var material = Crypto.HkdfSha256(secret, salt, info, 88);
        var c2sKey = material.AsSpan(0, 32).ToArray();
        var c2sNonce = material.AsSpan(32, 12).ToArray();
        var s2cKey = material.AsSpan(44, 32).ToArray();
        var s2cNonce = material.AsSpan(76, 12).ToArray();

        CryptographicOperations.ZeroMemory(material);
        return role == Role.Client
            ? new(c2sKey, s2cKey, c2sNonce, s2cNonce, sessionBytes, sessionId, role)
            : new(s2cKey, c2sKey, s2cNonce, c2sNonce, sessionBytes, sessionId, role);
    }

    public byte[] EncryptMessage(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> context = default)
    {
        ThrowIfDisposed();
        using var output = new MemoryStream();
        var offset = 0;
        while (offset < plaintext.Length)
        {
            var count = Math.Min(MaxRecordPayloadLength, plaintext.Length - offset);
            var data = EncryptRecord(plaintext.Slice(offset, count), context, close: false);
            output.Write(data);
            offset += count;
        }
        var close = EncryptRecord(ReadOnlySpan<byte>.Empty, context, close: true);
        output.Write(close);
        return output.ToArray();
    }

    public byte[] DecryptMessage(ReadOnlySpan<byte> records, ReadOnlySpan<byte> context = default)
    {
        ThrowIfDisposed();
        using var output = new MemoryStream();
        var offset = 0;
        var closed = false;
        while (offset < records.Length)
        {
            var (type, plaintext, consumed) = DecryptRecord(records[offset..], context);
            offset += consumed;
            if (type == RecordType.Close)
            {
                closed = true;
                if (offset != records.Length) throw new CryptographicException("Data follows the authenticated close record.");
                break;
            }
            output.Write(plaintext);
        }
        if (!closed) throw new CryptographicException("REST record sequence ended before authenticated close.");
        return output.ToArray();
    }

    public byte[] EncryptRecord(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> context = default, bool close = false)
    {
        ThrowIfDisposed();
        if (_sendClosed) throw new CryptographicException("Cannot write after the authenticated close record.");
        if (payload.Length > MaxRecordPayloadLength || (close && !payload.IsEmpty)) throw new CryptographicException("Invalid record payload.");
        if (_sendSequence == ulong.MaxValue) throw new CryptographicException("Record sequence exhausted.");
        
        var type = close ? RecordType.Close : RecordType.Data;
        var sequence = _sendSequence++;
        var cipher = new byte[payload.Length]; 
        var tag = new byte[Crypto.TagLength];
        var nonce = MakeNonce(_sendNonceBase, sequence);
        var aad = MakeAad(type, sequence, context, Role == Role.Client ? "client-to-server" : "server-to-client");
        
        using (var aes = new AesGcm(_sendKey, Crypto.TagLength))
            aes.Encrypt(nonce, payload, cipher, tag, aad);

        var bodyLength = RecordHeaderLength + cipher.Length + tag.Length;
        var frame = new byte[4 + bodyLength];
        BinaryPrimitives.WriteUInt32BigEndian(frame, checked((uint)bodyLength));
        frame[4] = (byte)type;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(5, 8), sequence);
        cipher.CopyTo(frame, 13); 
        tag.CopyTo(frame, 13 + cipher.Length);
        
        if (close) 
            _sendClosed = true;
            
        return frame;
    }

    public (RecordType Type, byte[] Plaintext, int Consumed) DecryptRecord(ReadOnlySpan<byte> frame, ReadOnlySpan<byte> context = default)
    {
        ThrowIfDisposed();
        if (_receiveClosed) throw new CryptographicException("Data follows the authenticated close record.");
        if (frame.Length < 4) throw new CryptographicException("Truncated record length.");
        
        var bodyLength = BinaryPrimitives.ReadUInt32BigEndian(frame);
        if (bodyLength < RecordHeaderLength + Crypto.TagLength || 
            bodyLength > RecordHeaderLength + MaxRecordPayloadLength + Crypto.TagLength)
            throw new CryptographicException("Invalid record length.");
        
        var total = checked((int)bodyLength + 4);
        if (frame.Length < total) 
            throw new CryptographicException("Truncated record.");
        
        var body = frame.Slice(4, (int)bodyLength);
        var type = (RecordType)body[0];
        if (type is not (RecordType.Data or RecordType.Close)) 
            throw new CryptographicException("Unknown record type.");
        
        var sequence = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(1, 8));
        if (sequence != _receiveSequence) throw new CryptographicException("Out-of-order or replayed record.");
        if (sequence == ulong.MaxValue) throw new CryptographicException("Record sequence exhausted.");
        
        var cipherLength = body.Length - RecordHeaderLength - Crypto.TagLength;
        if (type == RecordType.Close && cipherLength != 0) 
            throw new CryptographicException("Close record must be empty.");
        
        var plaintext = new byte[cipherLength];
        var nonce = MakeNonce(_receiveNonceBase, sequence);
        var aad = MakeAad(type, sequence, context, Role == Role.Client ? "server-to-client" : "client-to-server");
        using (var aes = new AesGcm(_receiveKey, Crypto.TagLength))
            aes.Decrypt(nonce, body.Slice(RecordHeaderLength, cipherLength), body[^Crypto.TagLength..], plaintext, aad);
        
        _receiveSequence++;
        if (type == RecordType.Close) _receiveClosed = true;
        return (type, plaintext, total);
    }

    internal static byte[] MakeAad(RecordType type, ulong sequence, ReadOnlySpan<byte> context, string direction)
    {
        Span<byte> sequenceBytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(sequenceBytes, sequence);
        return Crypto.HashTranscript(Encoding.UTF8.GetBytes(Crypto.ProtocolVersion), Encoding.UTF8.GetBytes(direction), new[] { (byte)type }, sequenceBytes.ToArray(), context.ToArray());
    }

    private static byte[] MakeNonce(byte[] basis, ulong sequence)
    {
        var nonce = basis.ToArray();
        Span<byte> seq = stackalloc byte[8]; 
        BinaryPrimitives.WriteUInt64BigEndian(seq, sequence);
        for (var i = 0; i < 8; i++) 
            nonce[4 + i] ^= seq[i];
        return nonce;
    }

    private void ThrowIfDisposed() { if (_disposed) throw new ObjectDisposedException(nameof(Session)); }

    public void Dispose()
    {
        if (_disposed) 
            return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_sendKey); 
        CryptographicOperations.ZeroMemory(_receiveKey);
        CryptographicOperations.ZeroMemory(_sendNonceBase); 
        CryptographicOperations.ZeroMemory(_receiveNonceBase);
    }
}

public enum RecordType : byte 
{ 
    Data = 1,
    Close = 2 
}
