using System;
using System.Threading;
using System.Threading.Tasks;
using Dapper;
using Microsoft.Data.Sqlite;

namespace EphemeralDH.Server.Data;

public sealed class SqliteUserStore(IUnitOfWork uow) : IUserStore
{
    private readonly IUnitOfWork _uow = uow;

    public async Task<UserRecord?> FindByUsernameAsync(string username, CancellationToken ct = default)
    {
        var conn = _uow.Connection;
        const string sql = @"
        SELECT
            id,
            username,
            password_hash AS PasswordHash,
            password_salt AS PasswordSalt,
            password_iterations AS PasswordIterations,
            is_admin AS Is_admin,
            created_at AS CreatedAtUnixSeconds
        FROM users
        WHERE username = @username
        ";

        var row = await conn.QuerySingleOrDefaultAsync<UserRow>(
            new CommandDefinition(sql, new { username }, transaction: _uow.Transaction, cancellationToken: ct));
        if (row is null)
        {
            return null;
        }

        var createdAt = DateTimeOffset.FromUnixTimeSeconds(row.CreatedAtUnixSeconds);

        return new UserRecord(row.Id, row.Username, row.IsAdmin, createdAt, row.PasswordSalt, row.PasswordHash, row.PasswordIterations);
    }

    public async Task<(bool ok, bool isAdmin)> ValidateCredentialsAsync(string username, string password, CancellationToken ct = default)
    {
        var user = await FindByUsernameAsync(username, ct);
        if (user is null)
        {
            return (ok: false, isAdmin: false);
        }

        var ok = PasswordHasher.VerifyPassword(password, user.PasswordSalt, user.PasswordHash, user.PasswordIterations);
        return (ok, isAdmin: user.IsAdmin);
    }

    public async Task<UserRecord> CreateUserAsync(string username, string password, bool isAdmin, CancellationToken ct = default)
    {
        var (salt, hash, iterations) = PasswordHasher.HashPassword(password);
        var now = DateTimeOffset.UtcNow;
        var createdAtUnixSeconds = now.ToUnixTimeSeconds();

        var conn = _uow.Connection;
        const string sql = @"
        INSERT INTO users (username, password_hash, password_salt, password_iterations, is_admin, created_at)
        VALUES (@username, @hash, @salt, @iterations, @is_admin, @created_at);
        SELECT last_insert_rowid();
        ";

        try
        {
            var id = await conn.ExecuteScalarAsync<long>(
                new CommandDefinition(sql, new
                {
                    username,
                    hash,
                    salt,
                    iterations,
                    is_admin = isAdmin ? 1 : 0,
                    created_at = createdAtUnixSeconds
                }, transaction: _uow.Transaction, cancellationToken: ct));

            return new UserRecord(id, username, isAdmin, now, salt, hash, iterations);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // constraint violation
        {
            throw new DuplicateUsernameException(username, ex);
        }
    }

    private sealed class UserRow
    {
        public long Id { get; init; }
        public string Username { get; init; } = string.Empty;
        public byte[] PasswordHash { get; init; } = [];
        public byte[] PasswordSalt { get; init; } = [];
        public int PasswordIterations { get; init; }
        public int Is_admin { get; init; }
        public long CreatedAtUnixSeconds { get; init; }

        public bool IsAdmin => Is_admin == 1;
    }
}

public sealed class DuplicateUsernameException(string username, Exception? inner) : Exception($"User '{username}' already exists.", inner)
{
    public string Username { get; } = username;
}
