using System.Security.Cryptography.X509Certificates;

namespace SigningServer.Contracts
{
    public interface ISigningTool
    {
        bool IsFileSupported(string fileName);
        string[] SupportedFileExtensions { get; }
        string[] SupportedHashAlgorithms { get; }

        void SignFile(string inputFileName, X509Certificate2 certificate, string timestampServer,SignFileRequest signFileRequest, SignFileResponse signFileResponse);
        bool IsFileSigned(string inputFileName);
        void UnsignFile(string inputFileName);
    }
}