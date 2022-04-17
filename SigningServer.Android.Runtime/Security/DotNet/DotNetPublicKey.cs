using System.Security.Cryptography;

namespace SigningServer.Android.Security.DotNet
{
    public interface DotNetPublicKey : PublicKey, CryptographyProviderAccessor
    {
        bool VerifyHash(byte[] digest, HashAlgorithmName digestName, byte[] signature);
    }
}