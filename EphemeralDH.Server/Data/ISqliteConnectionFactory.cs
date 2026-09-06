using System.Data;

namespace EphemeralDH.Server.Data;

public interface ISqliteConnectionFactory
{
    IDbConnection CreateConnection();
}

