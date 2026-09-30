using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using EphemeralDH.Core;

namespace EphemeralDH.Middleware;

public interface ISessionStore
{
    void Add(string sessionId, Session session, DateTimeOffset expiresAt);
    bool TryTake(string sessionId, DateTimeOffset now, out Session? session);
}

/// <summary>
/// Bounded process-local default. 
/// For applications with multiple instances better inject a shared implementation.</summary>
public sealed class InMemorySessionStore : ISessionStore, IDisposable
{
    private sealed record Entry(Session Session, DateTimeOffset ExpiresAt);
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly Timer _pruneTimer;
    private readonly int _capacity;
    private bool _disposed;

    public InMemorySessionStore(int capacity = 4096, TimeSpan? pruneInterval = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity, nameof(capacity));
        _capacity = capacity;
        var interval = pruneInterval ?? TimeSpan.FromSeconds(15);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(interval, TimeSpan.Zero, nameof(pruneInterval));

        _pruneTimer = new Timer(static state => ((InMemorySessionStore)state!).PruneExpired(), this, interval, interval);
    }

    public void Add(string sessionId, Session session, DateTimeOffset expiresAt)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(expiresAt, DateTimeOffset.UtcNow);
        lock (_gate)
        {
            if (_disposed)
            {
                session.Dispose();
                throw new ObjectDisposedException(nameof(InMemorySessionStore));
            }

            if (_entries.Count >= _capacity)
                PruneExpiredEntries(DateTimeOffset.UtcNow);

            if (_entries.TryAdd(sessionId, new Entry(session, expiresAt))) 
                return;
            session.Dispose();
            throw new InvalidOperationException("Session identifier collision.");
        }
    }

    public bool TryTake(string sessionId, DateTimeOffset now, out Session? session)
    {
        session = null;
        if (!_entries.TryRemove(sessionId, out var entry)) 
            return false;
        if (entry.ExpiresAt <= now) 
        { 
            entry.Session.Dispose(); 
            return false;
        }
        session = entry.Session;
        return true;
    }

    private void PruneExpired()
    {
        lock (_gate)
        {
            if (!_disposed)
                PruneExpiredEntries(DateTimeOffset.UtcNow);
        }
    }

    private void PruneExpiredEntries(DateTimeOffset now)
    {
        foreach (var pair in _entries)
            if (pair.Value.ExpiresAt <= now && _entries.Remove(pair.Key, out _))
                pair.Value.Session.Dispose();
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
                return;

            _disposed = true;
            _pruneTimer.Dispose();
            foreach (var pair in _entries)
                if (_entries.Remove(pair.Key, out _))
                    pair.Value.Session.Dispose();
        }
    }
}
