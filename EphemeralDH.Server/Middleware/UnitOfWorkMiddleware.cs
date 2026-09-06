using System.Threading.Tasks;
using EphemeralDH.Server.Data;
using Microsoft.AspNetCore.Http;

namespace EphemeralDH.Server.Middleware;

public sealed class UnitOfWorkMiddleware(RequestDelegate next)
{
    private readonly RequestDelegate _next = next;

    public async Task InvokeAsync(HttpContext context, IUnitOfWork uow)
    {
        try
        {
            await _next(context);
            await uow.CommitAsync(context.RequestAborted);
        }
        catch
        {
            await uow.RollbackAsync(context.RequestAborted);
            throw;
        }
        finally
        {
            // TODO: check transaction scope + ms di container integration
            // Let DI dispose the connection (SqliteConnection implements IDisposable).
            // If your DI container doesn’t dispose scoped services automatically, 
            // consider explicitly disposing here.
        }
    }
}

