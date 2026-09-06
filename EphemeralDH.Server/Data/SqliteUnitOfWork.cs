using System.Data;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace EphemeralDH.Server.Data;

public sealed class SqliteUnitOfWork : IUnitOfWork
{
    private readonly ISqliteConnectionFactory _connectionFactory;

    public SqliteUnitOfWork(ISqliteConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
        Connection = _connectionFactory.CreateConnection();
        Transaction = Connection.BeginTransaction();
    }

    public IDbConnection Connection { get; }
    public IDbTransaction Transaction { get; }

    public Task BeginAsync(System.Threading.CancellationToken ct = default)
        => Task.CompletedTask;

    public Task CommitAsync(System.Threading.CancellationToken ct = default)
    {
        Transaction.Commit();
        return Task.CompletedTask;
    }

    public Task RollbackAsync(System.Threading.CancellationToken ct = default)
    {
        Transaction.Rollback();
        return Task.CompletedTask;
    }
}

