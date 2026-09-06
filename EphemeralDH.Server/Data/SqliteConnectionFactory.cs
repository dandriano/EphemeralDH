using System;
using System.Data;
using System.IO;
using Microsoft.Data.Sqlite;

namespace EphemeralDH.Server.Data;

public sealed class SqliteConnectionFactory : ISqliteConnectionFactory
{
    public string DbPath { get; }

    public SqliteConnectionFactory()
    {
        var envPath = Environment.GetEnvironmentVariable("EDHX_DB_PATH");
        DbPath = string.IsNullOrWhiteSpace(envPath)
            ? Path.Combine(Directory.GetCurrentDirectory(), "app.db")
            : envPath;
    }

    public IDbConnection CreateConnection()
    {
        var connString = $"Data Source={DbPath};Cache=Shared";
        var conn = new SqliteConnection(connString);
        conn.Open();
        return conn;
    }
}
