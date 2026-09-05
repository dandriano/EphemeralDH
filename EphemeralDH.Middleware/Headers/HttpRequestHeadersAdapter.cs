using EphemeralDH.Core;

namespace EphemeralDH.Middleware.Headers;

internal sealed class HttpRequestHeadersAdapter(Microsoft.AspNetCore.Http.HttpRequest request) : IProtocolHeaderReader
{
    private readonly Microsoft.AspNetCore.Http.HttpRequest _request = request;

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

