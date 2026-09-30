using EphemeralDH.Core;
using Microsoft.AspNetCore.Http;

namespace EphemeralDH.Middleware.Headers;

internal sealed class HttpRequestHeadersAdapter(HttpRequest request) : IHeaderReader
{
    private readonly HttpRequest _request = request;

    public bool TryGetHeader(string name, out string? value)
    {
        if (_request.Headers.TryGetValue(name, out var values) && values.Count > 0)
        {
            value = values.ToString();
            return !string.IsNullOrWhiteSpace(value);
        }

        value = null;
        return false;
    }
}

