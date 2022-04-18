using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SigningServer.Core;

public class SignFileRequest
{
    public string InputFilePath { get; set; }
    public X509Certificate2 Certificate { get; set; }
    public AsymmetricAlgorithm PrivateKey { get; set; }
    public string InputRawFileName { get; set; }
    public string TimestampServer { get; set; }
    public string HashAlgorithm { get; set; }
    public bool OverwriteSignature { get; set; }
}
