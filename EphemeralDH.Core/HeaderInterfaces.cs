namespace EphemeralDH.Core;

public interface IHeaderReader
{
    bool TryGetHeader(string name, out string? value);
}

public interface IHeaderWriter
{
    void SetHeader(string name, string value);
    void RemoveHeader(string name);
}

