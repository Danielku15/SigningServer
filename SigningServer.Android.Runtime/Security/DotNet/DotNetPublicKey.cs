using System.Security.Cryptography;

namespace SigningServer.Android.Security.DotNet
{
    internal interface DotNetPublicKey : PublicKey, CryptographyProviderAccessor
    {
        bool VerifyHash(byte[] digest, HashAlgorithmName digestName, byte[] signature);
    }
}