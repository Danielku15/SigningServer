namespace SigningServer.Contracts;

public interface ISigningToolProvider
{
    ISigningTool GetSigningTool(string fileName);
    string[] SupportedFileExtensions { get; }
    string[] SupportedHashAlgorithms { get; }
}