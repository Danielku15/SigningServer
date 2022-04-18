namespace SigningServer.Core;

public interface ISigningTool
{
    string Name { get; }
    string[] SupportedFileExtensions { get; }
    string[] SupportedHashAlgorithms { get; }

    bool IsFileSupported(string fileName);
    
    SignFileResponse SignFile(SignFileRequest signFileRequest);

    bool IsFileSigned(string inputFileName);
}
