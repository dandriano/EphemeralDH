using System;
using System.Security.Cryptography;
using System.Text;

namespace EphemeralDH.Core;

public static class BasicAuthCodec
{
    public static string ReadBearerCredential(System.Net.Http.Headers.AuthenticationHeaderValue? header)
    {
        if (header is null || !string.Equals(header.Scheme, "Basic", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(header.Parameter))
        {
            throw new CryptographicException("Missing or invalid Basic authorization header.");
        }

        var decoded = Convert.FromBase64String(header.Parameter);
        return Encoding.UTF8.GetString(decoded);
    }

    public static (string Username, string Password) ReadBasicAuth(System.Net.Http.Headers.AuthenticationHeaderValue? header)
    {
        var credential = ReadBearerCredential(header);
        var separator = credential.IndexOf(':');
        if (separator <= 0)
        {
            throw new CryptographicException("Invalid Basic authorization credential.");
        }

        return (credential[..separator], credential[(separator + 1)..]);
    }

    public static System.Net.Http.Headers.AuthenticationHeaderValue CreateBasicAuth(string username, string password)
        => new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}")));
}

