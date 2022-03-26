using System;
using System.Security.Cryptography.X509Certificates;

namespace SigningServer.Contracts
{
    public interface ISigningCertificate : IDisposable
    {
        string SubjectName { get; }
        byte[] GetRawCertData();
        X509Certificate2 ToX509();
    }
    
    public interface ISigningTool
    {
        bool IsFileSupported(string fileName);
        string[] SupportedFileExtensions { get; }
        string[] SupportedHashAlgorithms { get; }

        void SignFile(string inputFileName, ISigningCertificate certificate, string timestampServer,SignFileRequest signFileRequest, SignFileResponse signFileResponse);
        bool IsFileSigned(string inputFileName);
    }
}