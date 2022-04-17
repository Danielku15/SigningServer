using System.Security.Cryptography;

namespace SigningServer.Android.Security.DotNet
{
    public interface DotNetPrivateKey : PrivateKey, CryptographyProviderAccessor
    {
        byte[] SignHash(byte[] digest, HashAlgorithmName digestName);
    }
}