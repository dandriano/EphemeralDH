using EphemeralDH.Core;

namespace EphemeralDH.Middleware.Headers;

internal sealed class HttpResponseHeadersAdapter(Microsoft.AspNetCore.Http.HttpResponse response) : IProtocolHeaderWriter
{
    private readonly Microsoft.AspNetCore.Http.HttpResponse _response = response;

    public void SetHeader(string name, string value)
        => _response.Headers[name] = value;

    public void RemoveHeader(string name)
        => _response.Headers.Remove(name);
}

