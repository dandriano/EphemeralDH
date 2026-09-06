using System;
using System.Threading;
using System.Threading.Tasks;

namespace EphemeralDH.Server.Data;

public interface IUserStore
{
    Task<UserRecord?> FindByUsernameAsync(string username, CancellationToken ct = default);
    Task<(bool ok, bool isAdmin)> ValidateCredentialsAsync(string username, string password, CancellationToken ct = default);
    Task<UserRecord> CreateUserAsync(string username, string password, bool isAdmin, CancellationToken ct = default);
}

public sealed record UserRecord(long Id, string Username, bool IsAdmin, DateTimeOffset CreatedAt,
    byte[] PasswordSalt, byte[] PasswordHash, int PasswordIterations);

