using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using EphemeralDH.Core;

namespace EphemeralDH.Client;

internal static class Program
{
    private const string Host = "127.0.0.1";
    private const int Port = 8080;
    private const string AdminUsername = "admin";
    private const string AdminPassword = "admin";

    public static async Task Main()
    {
        using var http = new HttpClient
        {
            BaseAddress = new Uri($"http://{Host}:{Port}", UriKind.Absolute),
        };

        // 1) Health
        await SendDebugAsync(http, HttpMethod.Get, "/health");

        // 2) /users auth failures
        await SendDebugAsync(
            http,
            HttpMethod.Post,
            "/users",
            headers: null,
            bodyString: JsonSerializer.Serialize(new { username = "bob", password = "password123", isAdmin = false }),
            contentType: "application/json");

        // 3) Create a non-admin user (admin-only)
        var adminAuthB64 = CreateBasicAuthValue(AdminUsername, AdminPassword);
        await SendDebugAsync(
            http,
            HttpMethod.Post,
            "/users",
            headers: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = $"Basic {adminAuthB64}",
            },
            bodyString: JsonSerializer.Serialize(new { username = "bob", password = "password123", isAdmin = false }),
            contentType: "application/json");

        // 4) /users with non-admin should be forbidden
        var bobAuthB64 = CreateBasicAuthValue("bob", "password123");
        await SendDebugAsync(
            http,
            HttpMethod.Post,
            "/users",
            headers: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = $"Basic {bobAuthB64}",
            },
            bodyString: JsonSerializer.Serialize(new { username = "charlie", password = "password123", isAdmin = false }),
            contentType: "application/json");

        // 5) /echo encryption endpoint
        Console.WriteLine("\n==> /echo negative case (missing client public key)");
        await SendDebugAsync(
            http,
            HttpMethod.Post,
            "/echo",
            headers: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = $"Basic {adminAuthB64}",
            },
            bodyString: CreateEchoPayloadJson(),
            contentType: "application/json");

        Console.WriteLine("\n==> /echo positive case (encrypted response)");
        using var clientEphemeral = CryptoCore.CreateEphemeralKey();
        var clientPublicKey = CryptoCore.EncodePublicKey(clientEphemeral.PublicKey);
        var clientPubB64 = Convert.ToBase64String(clientPublicKey);
        Console.WriteLine($"Client public key (base64, hidden length={clientPubB64.Length})");

        var echoResponse = await SendDebugAsync(
            http,
            HttpMethod.Post,
            "/echo",
            headers: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = $"Basic {adminAuthB64}",
                [ProtocolCodec.ClientPublicKeyHeader] = clientPubB64,
            },
            bodyString: CreateEchoPayloadJson(),
            contentType: "application/json");

        TryDecryptEchoResponse(
            echoResponse,
            clientEphemeral,
            method: "POST",
            path: "/echo",
            identity: AdminUsername);

        Console.WriteLine("\nDone.");
    }

    private static string CreateBasicAuthValue(string username, string password)
    {
        var raw = $"{username}:{password}";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
    }

    private static string CreateEchoPayloadJson()
    {
        var requestId = Random.Shared.Next(0, 1_000_000).ToString(CultureInfo.InvariantCulture);
        return JsonSerializer.Serialize(new { message = "hello", value = 42, request = requestId });
    }

    private static async Task<DebugResponse> SendDebugAsync(
        HttpClient http,
        HttpMethod method,
        string path,
        IReadOnlyDictionary<string, string>? headers = null,
        string? bodyString = null,
        string? contentType = null,
        CancellationToken ct = default)
    {
        var absoluteUrl = new Uri(http.BaseAddress!, path);

        Console.WriteLine("\n==> Request");
        Console.WriteLine($"METHOD: {method.Method}");
        Console.WriteLine($"URL: {absoluteUrl}");

        var hasAuth = false;
        var hasClientPub = false;

        if (headers is not null)
        {
            foreach (var (name, value) in headers)
            {
                if (name.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                {
                    hasAuth = true;
                    Console.WriteLine("Header: Authorization: Basic ***");
                    continue;
                }

                if (name.Equals(ProtocolCodec.ClientPublicKeyHeader, StringComparison.OrdinalIgnoreCase))
                {
                    hasClientPub = true;
                    Console.WriteLine($"Header: {ProtocolCodec.ClientPublicKeyHeader}: *** (len={value.Length})");
                    continue;
                }

                Console.WriteLine($"Header: {name}: ***");
            }
        }

        if (!hasAuth)
        {
            Console.WriteLine("Header: Authorization: (not set)");
        }

        if (!hasClientPub)
        {
            Console.WriteLine($"Header: {ProtocolCodec.ClientPublicKeyHeader}: (not set)");
        }

        using var request = new HttpRequestMessage(method, path);

        if (headers is not null)
        {
            foreach (var (name, value) in headers)
            {
                if (name.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                {
                    var spaceIdx = value.IndexOf(' ');
                    var scheme = spaceIdx >= 0 ? value[..spaceIdx] : "Basic";
                    var parameter = spaceIdx >= 0 ? value[(spaceIdx + 1)..] : value;
                    request.Headers.Authorization = new AuthenticationHeaderValue(scheme, parameter);
                    continue;
                }

                request.Headers.TryAddWithoutValidation(name, value);
            }
        }

        if (bodyString is not null)
        {
            var ctValue = string.IsNullOrWhiteSpace(contentType) ? "application/json" : contentType;
            request.Content = new StringContent(bodyString, Encoding.UTF8, ctValue);
            Console.WriteLine($"Header: Content-Type: {ctValue}");
            Console.WriteLine($"Body: {Encoding.UTF8.GetByteCount(bodyString)} bytes");
            Console.WriteLine($"Body preview: {Truncate(bodyString, 200)}");
        }

        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        var bodyBytes = response.Content is null ? Array.Empty<byte>() : await response.Content.ReadAsByteArrayAsync(ct);

        Console.WriteLine($"\n==> {method.Method} {absoluteUrl}");
        Console.WriteLine($"<== HTTP {(int)response.StatusCode} {response.ReasonPhrase}");

        var combinedHeaders = GetAllHeaders(response);
        Console.WriteLine("-- Response headers --");
        foreach (var (name, values) in combinedHeaders.OrderBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase))
        {
            Console.WriteLine($"{name}: {string.Join(", ", values)}");
        }

        Console.WriteLine("-- Response body preview --");
        var responseContentType = response.Content?.Headers?.ContentType?.ToString();
        if (responseContentType is not null && responseContentType.StartsWith("application/octet-stream", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"[binary] bytes={bodyBytes.Length}");
            Console.WriteLine("[hexdump: first 64 bytes]");
            Console.WriteLine(HexDump(bodyBytes, 64));
            Console.WriteLine("[base64: first 120 chars]");
            Console.WriteLine(Truncate(Convert.ToBase64String(bodyBytes), 120));
        }
        else
        {
            Console.WriteLine("[text preview: up to 200 bytes]");
            Console.WriteLine(PreviewUtf8(bodyBytes, 200));
        }

        return new DebugResponse(response.StatusCode, combinedHeaders, responseContentType, bodyBytes);
    }

    private static void TryDecryptEchoResponse(DebugResponse response, ECDiffieHellman clientEphemeral, string method, string path, string identity)
    {
        if (response.StatusCode != HttpStatusCode.OK)
        {
            Console.WriteLine($"\nDecryption skipped (HTTP {(int)response.StatusCode}).");
            return;
        }

        try
        {
            var protocolVersion = ReadRequiredHeader(response.Headers, ProtocolCodec.ProtocolVersionHeader);
            var serverPublicKeyB64 = ReadRequiredHeader(response.Headers, ProtocolCodec.ServerPublicKeyHeader);
            var nonceB64 = ReadRequiredHeader(response.Headers, ProtocolCodec.NonceHeader);
            var tagB64 = ReadRequiredHeader(response.Headers, ProtocolCodec.TagHeader);

            var serverPublicKey = Convert.FromBase64String(serverPublicKeyB64);
            var nonce = Convert.FromBase64String(nonceB64);
            var tag = Convert.FromBase64String(tagB64);

            var requestSalt = CryptoCore.DeriveRequestSalt(method, path, identity);
            var sharedSecret = CryptoCore.DeriveSharedSecret(clientEphemeral, serverPublicKey);
            var info = Encoding.UTF8.GetBytes(path);
            var sessionKey = CryptoCore.DeriveSessionKey(sharedSecret, requestSalt, info);
            var aad = CryptoCore.BuildAssociatedData(protocolVersion, method, path, identity);

            var plaintext = CryptoCore.DecryptResponse(sessionKey, response.BodyBytes, nonce, tag, aad);
            Console.WriteLine("\n-- Decrypted /echo response --");
            Console.WriteLine(PreviewUtf8(plaintext, 400));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nDecryption failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static Dictionary<string, string[]> GetAllHeaders(HttpResponseMessage response)
    {
        var headers = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        void Add(string name, IEnumerable<string> values)
        {
            if (!headers.TryGetValue(name, out var list))
            {
                list = new List<string>();
                headers[name] = list;
            }

            list.AddRange(values);
        }

        foreach (var header in response.Headers)
        {
            Add(header.Key, header.Value);
        }

        foreach (var header in response.Content.Headers)
        {
            Add(header.Key, header.Value);
        }

        return headers.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.ToArray(), StringComparer.OrdinalIgnoreCase);
    }

    private static string ReadRequiredHeader(IReadOnlyDictionary<string, string[]> headers, string name)
    {
        if (!headers.TryGetValue(name, out var values) || values.Length == 0 || string.IsNullOrWhiteSpace(values[0]))
        {
            throw new InvalidOperationException($"Missing required header {name}.");
        }

        return values[0];
    }

    private static string HexDump(byte[] bytes, int maxBytes)
    {
        var len = Math.Min(bytes.Length, maxBytes);
        if (len == 0)
        {
            return string.Empty;
        }

        var sb = new StringBuilder(len * 3);
        for (var i = 0; i < len; i++)
        {
            if (i > 0)
            {
                sb.Append(' ');
            }

            sb.Append(bytes[i].ToString("x2", CultureInfo.InvariantCulture));
        }

        return sb.ToString();
    }

    private static string PreviewUtf8(byte[] bytes, int maxBytes)
    {
        if (bytes.Length == 0)
        {
            return string.Empty;
        }

        var len = Math.Min(bytes.Length, maxBytes);
        try
        {
            return Encoding.UTF8.GetString(bytes, 0, len);
        }
        catch
        {
            return $"[non-utf8] base64={Truncate(Convert.ToBase64String(bytes), 200)}";
        }
    }

    private static string Truncate(string value, int maxChars)
    {
        if (value.Length <= maxChars)
        {
            return value;
        }

        return value[..maxChars];
    }

    private sealed record DebugResponse(
        HttpStatusCode StatusCode,
        IReadOnlyDictionary<string, string[]> Headers,
        string? ContentType,
        byte[] BodyBytes);
}
