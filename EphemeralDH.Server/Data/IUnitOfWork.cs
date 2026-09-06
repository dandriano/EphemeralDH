using System.Data;
using System.Threading;
using System.Threading.Tasks;

namespace EphemeralDH.Server.Data;

public interface IUnitOfWork
{
    IDbConnection Connection { get; }
    IDbTransaction Transaction { get; }

    Task BeginAsync(CancellationToken ct = default);
    Task CommitAsync(CancellationToken ct = default);
    Task RollbackAsync(CancellationToken ct = default);
}

