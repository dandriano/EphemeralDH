using System;
using System.IO;
using Dapper;
using Microsoft.Data.Sqlite;

namespace EphemeralDH.Server.Data;

public sealed class DbInitializer
{
    public static string NormalizeUsername(string username)
        => username.Trim().ToLowerInvariant();

    private const string CreateUsersTableSql = @"
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash BLOB NOT NULL,
        password_salt BLOB NOT NULL,
        password_iterations INTEGER NOT NULL,
        is_admin INTEGER NOT NULL,
        created_at INTEGER NOT NULL
        );
    ";

    public void InitializeAndSeedAdmin(ISqliteConnectionFactory connectionFactory)
    {
        var dbPath = GetDbPathFromFactory(connectionFactory);
        if (dbPath is not null)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(dbPath) ?? ".");
        }

        using var conn = (SqliteConnection)connectionFactory.CreateConnection();
        conn.Execute(CreateUsersTableSql);

        var adminUsername = Environment.GetEnvironmentVariable("EDHX_ADMIN_USERNAME");
        var adminPassword = Environment.GetEnvironmentVariable("EDHX_ADMIN_PASSWORD");
        if (string.IsNullOrWhiteSpace(adminUsername))
            throw new InvalidOperationException("Missing required env var EDHX_ADMIN_USERNAME");

        if (string.IsNullOrWhiteSpace(adminPassword))
            throw new InvalidOperationException("Missing required env var EDHX_ADMIN_PASSWORD");

        adminUsername = NormalizeUsername(adminUsername);

        var exists = conn.ExecuteScalar<int>(
            "SELECT COUNT(1) FROM users WHERE username = @username",
            new { username = adminUsername });

        if (exists > 0)
        {
            return;
        }

        var (salt, hash, iterations) = PasswordHasher.HashPassword(adminPassword);
        var now = DateTimeOffset.UtcNow;
        var createdAtUnixSeconds = now.ToUnixTimeSeconds();
        conn.Execute(
            "INSERT INTO users (username, password_hash, password_salt, password_iterations, is_admin, created_at) VALUES (@username, @hash, @salt, @iterations, 1, @created_at)",
            new
            {
                username = adminUsername,
                hash,
                salt,
                iterations,
                created_at = createdAtUnixSeconds
            });
    }

    private static string? GetDbPathFromFactory(ISqliteConnectionFactory connectionFactory)
    {
        if (connectionFactory is not SqliteConnectionFactory sqlite)
            return null;

        return sqlite.DbPath;
    }
}
