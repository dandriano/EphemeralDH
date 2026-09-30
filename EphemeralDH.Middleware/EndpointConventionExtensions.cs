using Microsoft.AspNetCore.Builder;

namespace EphemeralDH.Middleware;

internal sealed class EncryptionRequiredMetadata;

public static class EndpointConventionExtensions
{
    public static TBuilder RequireEdhxEncryption<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        builder.Add(endpointBuilder =>
            endpointBuilder.Metadata.Add(new EncryptionRequiredMetadata()));
        return builder;
    }
}
