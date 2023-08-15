using System;
using System.Security.Cryptography;

namespace SigningServer.Dtos;

public record DecryptRsaRequestDto(string? Username, string? Password, string Data, string HashAlgorithmName,
    RSAEncryptionPaddingMode RsaPaddingMode)
{
    public RSAEncryptionPadding ToPadding()
    {
        switch (RsaPaddingMode)
        {
            case RSAEncryptionPaddingMode.Pkcs1:
                return RSAEncryptionPadding.Pkcs1;
            case RSAEncryptionPaddingMode.Oaep:
                switch (HashAlgorithmName)
                {
                    case "SHA1":
                    case "SHA-1":
                        return RSAEncryptionPadding.OaepSHA1;
                    case "SHA256":
                    case "SHA-256":
                        return RSAEncryptionPadding.OaepSHA256;
                    case "SHA386":
                    case "SHA-386":
                        return RSAEncryptionPadding.OaepSHA384;
                    case "SHA512":
                    case "SHA-512":
                        return RSAEncryptionPadding.OaepSHA512;
                    default:
                        throw new InvalidOperationException("Unsupported RSA Oaep hash: " + HashAlgorithmName);
                }
            default:
                throw new InvalidOperationException("Unsupported RSA Encryption Padding: " + RsaPaddingMode);
        }
    }
}
