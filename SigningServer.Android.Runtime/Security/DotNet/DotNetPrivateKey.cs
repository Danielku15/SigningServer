using System.Security.Cryptography;

namespace SigningServer.Android.Security.DotNet
{
    internal interface DotNetPrivateKey : PrivateKey, CryptographyProviderAccessor
    {
        byte[] SignHash(byte[] digest, HashAlgorithmName digestName);
    }
}