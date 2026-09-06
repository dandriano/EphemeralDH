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
    }
}

