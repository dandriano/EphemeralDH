using System;
using System.Security.Cryptography;

namespace EphemeralDH.Server.Data;

public static class PasswordHasher
{
    private const int DefaultIterations = 100_000;
    private const int SaltLength = 16; // bytes

    public static (byte[] salt, byte[] hash, int iterations) HashPassword(string password, int? iterations = null)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password must not be empty.", nameof(password));

        var actualIterations = iterations ?? DefaultIterations;
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        using var deriveBytes = new Rfc2898DeriveBytes(password, salt, actualIterations, HashAlgorithmName.SHA256);
        var hash = deriveBytes.GetBytes(32);

        return (salt, hash, actualIterations);
    }

    public static bool VerifyPassword(string password, byte[] salt, byte[] hash, int iterations)
    {
        using var deriveBytes = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        var candidate = deriveBytes.GetBytes(hash.Length);

        return CryptographicOperations.FixedTimeEquals(candidate, hash);
    }
}

