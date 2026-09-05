namespace EphemeralDH.Core;

public interface IProtocolHeaderReader
{
    bool TryGetHeader(string name, out string? value);
}

public interface IProtocolHeaderWriter
{
    void SetHeader(string name, string value);
    void RemoveHeader(string name);
}

