using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace EphemeralDH.Core;

/// <summary>
/// Authenticated record stream over an arbitrary duplex stream.
/// </summary>
public sealed class CryptoStream : Stream
{
    private readonly Stream _inner;
    private readonly Session _session;
    private readonly bool _leaveOpen;
    private readonly byte[] _context;
    private readonly SemaphoreSlim _readLock = new(1, 1), _writeLock = new(1, 1);
    private byte[] _pending = Array.Empty<byte>();
    private int _pendingOffset;
    private bool _readClosed, _writeClosed, _disposed;

    public CryptoStream(Stream inner, Session session, ReadOnlyMemory<byte> context = default, bool leaveOpen = false)
    {
        if (!inner.CanRead || !inner.CanWrite) throw new ArgumentException("The underlying stream must be readable and writable.", nameof(inner));
        _inner = inner; _session = session; _context = context.ToArray(); _leaveOpen = leaveOpen;
    }

    public override bool CanRead => !_disposed && _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => !_disposed && _inner.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, nameof(CryptoStream));
        if (buffer.IsEmpty) return 0;
        await _readLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_pendingOffset < _pending.Length) return CopyPending(buffer.Span);
            if (_readClosed) return 0;
            while (true)
            {
                var lengthBytes = new byte[4];
                var first = await _inner.ReadAsync(lengthBytes.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
                if (first == 0) throw new CryptographicException("Underlying stream ended before the authenticated close record.");
                await ReadExactlyAsync(_inner, lengthBytes.AsMemory(1), cancellationToken).ConfigureAwait(false);
                var bodyLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(lengthBytes);
                if (bodyLength < Session.RecordHeaderLength + Crypto.TagLength ||
                    bodyLength > Session.RecordHeaderLength + Session.MaxRecordPayloadLength + Crypto.TagLength)
                    throw new CryptographicException("Invalid record length.");
                var frame = new byte[checked((int)bodyLength + 4)];
                lengthBytes.CopyTo(frame, 0);
                await ReadExactlyAsync(_inner, frame.AsMemory(4), cancellationToken).ConfigureAwait(false);
                var (type, plaintext, _) = _session.DecryptRecord(frame, _context);
                if (type == RecordType.Close) { _readClosed = true; return 0; }
                _pending = plaintext; _pendingOffset = 0;
                if (_pending.Length == 0) continue;
                return CopyPending(buffer.Span);
            }
        }
        finally { _readLock.Release(); }
    }

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, nameof(CryptoStream));
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_writeClosed) throw new IOException("The authenticated write side is closed.");
            var offset = 0;
            while (offset < buffer.Length)
            {
                var count = Math.Min(Session.MaxRecordPayloadLength, buffer.Length - offset);
                var frame = _session.EncryptRecord(buffer.Span.Slice(offset, count), _context, close: false);
                await _inner.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
                offset += count;
            }
        }
        finally { _writeLock.Release(); }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async Task FlushAsync(CancellationToken cancellationToken)
        => await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);
    public override void Flush() => _inner.Flush();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    private int CopyPending(Span<byte> destination)
    {
        var count = Math.Min(destination.Length, _pending.Length - _pendingOffset);
        _pending.AsSpan(_pendingOffset, count).CopyTo(destination);
        _pendingOffset += count;
        if (_pendingOffset == _pending.Length) { _pending = Array.Empty<byte>(); _pendingOffset = 0; }
        return count;
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], ct).ConfigureAwait(false);
            if (read == 0) throw new CryptographicException("Underlying stream ended inside a record.");
            offset += read;
        }
    }

    private async Task CloseWriteAsync(CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_writeClosed) return;
            var frame = _session.EncryptRecord(ReadOnlySpan<byte>.Empty, _context, close: true);
            await _inner.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
            await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);
            _writeClosed = true;
        }
        finally { _writeLock.Release(); }
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            CloseWriteAsync(CancellationToken.None).GetAwaiter().GetResult();
            if (!_leaveOpen) _inner.Dispose();
            _disposed = true;
            _session.Dispose();
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            await CloseWriteAsync(CancellationToken.None).ConfigureAwait(false);
            if (!_leaveOpen) await _inner.DisposeAsync().ConfigureAwait(false);
            _disposed = true;
            _session.Dispose();
        }
        GC.SuppressFinalize(this);
    }
}
