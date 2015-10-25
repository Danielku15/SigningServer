using System.Security.Cryptography.X509Certificates;
using SigningServer.Contracts;

namespace SigningServer.Server
{
    class AndroidApkSigningTool : ISigningTool
    {
        public bool IsFileSupported(string fileName)
        {
            return false;
        }

        public void SignFile(string inputFileName, X509Certificate2 certificate, string timestampServer,
            SignFileRequest signFileRequest, SignFileResponse signFileResponse)
        {
        }

        public bool IsFileSigned(string inputFileName)
        {
            return false;
        }

        public void UnsignFile(string inputFileName)
        {
        }

        public string[] GetSupportedFileExtensions()
        {
            return new string[0];
        }
    }
}