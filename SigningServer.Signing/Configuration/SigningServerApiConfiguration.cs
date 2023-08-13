using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SigningServer.Core;
using SigningServer.Dtos;

namespace SigningServer.Signing.Configuration;

/// <summary>
/// Represents the settings to use a signing server for signing..
/// </summary>
public class SigningServerApiConfiguration
{
    /// <summary>
    /// The url to the signing server.
    /// </summary>
    public string SigningServer { get; set; } = string.Empty;

    /// <summary>
    /// The username for authentication and cerificate selection.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// The password for authentication and certificate selection.
    /// </summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// The timeout of signing operations in seconds.
    /// </summary>
    public int Timeout { get; set; } = 60;

    public void Load(ILogger logger, CertificateConfiguration certificateConfiguration)
    {
        logger.LogInformation("Loading Certificate from Signing Server");
        if (!Uri.TryCreate(SigningServer, UriKind.Absolute, out var signingServerUri))
        {
            throw new InvalidConfigurationException("Could not parse SigningServer URL, please specify absolute URL");
        }

        var client = new HttpClient { BaseAddress = signingServerUri, Timeout = TimeSpan.FromSeconds(Timeout) };

        certificateConfiguration.Certificate = LoadCertificate(client);

        if (certificateConfiguration.Certificate.GetRSAPublicKey() is { } rsa)
        {
            certificateConfiguration.PrivateKey = new RsaSigningServerPrivateKey(client,
                this,
                rsa);
        }
        else if (certificateConfiguration.Certificate.GetECDsaPublicKey() is { } ecdsa)
        {
            certificateConfiguration.PrivateKey = new ECDsaSigningServerPrivateKey(client,
                this,
                ecdsa);
        }
        else
        {
            throw new InvalidConfigurationException("Unsupported certificate type: " + certificateConfiguration.Certificate.PublicKey.Oid);
        }
    }

    private X509Certificate2 LoadCertificate(HttpClient client)
    {
        var response = client.Send(new HttpRequestMessage(HttpMethod.Post,  "signing/loadcertificate")
            {
                Content = JsonContent.Create(new LoadCertificateRequestDto
                {
                    Username = Username,
                    Password = Password,
                    ExportFormat = LoadCertificateFormat.Pkcs12,
                    IncludeChain = false
                })
            });

        using var stream = response.Content.ReadAsStream();
        var responseDto = System.Text.Json.JsonSerializer.Deserialize<LoadCertificateResponseDto>(stream);

        switch (responseDto!.Status)
        {
            case LoadCertificateResponseStatus.CertificateLoaded:
                return new X509Certificate2(Convert.FromBase64String(responseDto.CertificateData!));
            case LoadCertificateResponseStatus.CertificateNotLoadedError:
                throw new InvalidConfigurationException("Could not load certificate: " + responseDto.ErrorMessage);
            case LoadCertificateResponseStatus.CertificateNotLoadedUnauthorized:
                throw new InvalidConfigurationException("Could not load certificate: Permission Denied, " +
                                                        responseDto.ErrorMessage);
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    private class ECDsaSigningServerPrivateKey : ECDsa
    {
        private readonly HttpClient _client;
        private readonly SigningServerApiConfiguration _configuration;
        private readonly ECDsa _publicKey;

        public ECDsaSigningServerPrivateKey(HttpClient client, SigningServerApiConfiguration configuration,
            ECDsa publicKey)
        {
            _client = client;
            _configuration = configuration;
            _publicKey = publicKey;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _client.Dispose();
                _publicKey.Dispose();
            }

            base.Dispose(disposing);
        }

        public override ECParameters ExportParameters(bool includePrivateParameters)
        {
            return _publicKey.ExportParameters(includePrivateParameters);
        }

        public override ECParameters ExportExplicitParameters(bool includePrivateParameters)
        {
            return _publicKey.ExportExplicitParameters(false);
        }

        public override void ImportParameters(ECParameters parameters)
        {
            throw new NotSupportedException();
        }

        public override void GenerateKey(ECCurve curve)
        {
            throw new NotSupportedException();
        }

        public override byte[] SignHash(byte[] hash)
        {
            try
            {
                var response = _client.Send(new HttpRequestMessage(HttpMethod.Post, "signing/signhash")
                {
                    Content = JsonContent.Create(new SignHashRequestDto
                    {
                        Username = _configuration.Username,
                        Password = _configuration.Password,
                        Hash = Convert.ToBase64String(hash),
                        HashAlgorithm = "SHA256" // ignored
                    })
                });

                using var stream = response.Content.ReadAsStream();
                var responseDto = System.Text.Json.JsonSerializer.Deserialize<SignHashResponseDto>(stream);

                if (!string.IsNullOrEmpty(responseDto?.ErrorMessage))
                {
                    throw new CryptographicException(responseDto.ErrorMessage);
                }

                return Convert.FromBase64String(responseDto!.Signature);
            }
            catch (Exception e)
            {
                throw new CryptographicException("Error calling SigningServer", e);
            }
        }

        public override string ToXmlString(bool includePrivateParameters)
        {
            return _publicKey.ToXmlString(false);
        }

        public override void FromXmlString(string xmlString)
        {
            throw new NotSupportedException();
        }

        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            return _publicKey.VerifyHash(hash, signature);
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            using var hash = CreateHash(hashAlgorithm);
            return hash.ComputeHash(data, offset, count);
        }

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            using var hash = CreateHash(hashAlgorithm);
            return hash.ComputeHash(data);
        }
    }

    private class RsaSigningServerPrivateKey : RSA
    {
        private readonly HttpClient _client;
        private readonly SigningServerApiConfiguration _configuration;
        private readonly RSA _publicKey;

        public RsaSigningServerPrivateKey(HttpClient client,
            SigningServerApiConfiguration configuration,
            RSA publicKey)
        {
            _client = client;
            _configuration = configuration;
            _publicKey = publicKey;
        }


        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _client.Dispose();
                _publicKey.Dispose();
            }

            base.Dispose(disposing);
        }


        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            return _publicKey.ExportParameters(includePrivateParameters);
        }

        public override void ImportParameters(RSAParameters parameters)
        {
            throw new NotSupportedException();
        }

        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
        {
            return _publicKey.Encrypt(data, padding);
        }

        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        {
            try
            {
                var response = _client.Send(new HttpRequestMessage(HttpMethod.Post, "signing/decryptrsa")
                {
                    Content = JsonContent.Create(new DecryptRsaRequestDto(
                        _configuration.Username,
                        _configuration.Password,
                        Convert.ToBase64String(data),
                        padding.OaepHashAlgorithm.Name!,
                        padding.Mode))
                });

                using var stream = response.Content.ReadAsStream();
                var responseDto = System.Text.Json.JsonSerializer.Deserialize<DecryptRsaResponseDto>(stream);

                if (!string.IsNullOrEmpty(responseDto?.ErrorMessage))
                {
                    throw new CryptographicException(responseDto.ErrorMessage);
                }

                return Convert.FromBase64String(responseDto!.Data!);
            }
            catch (Exception e)
            {
                throw new CryptographicException("Error calling SigningServer", e);
            }
        }

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            try
            {
                var response = _client.Send(new HttpRequestMessage(HttpMethod.Post, "signing/signhash")
                {
                    Content = JsonContent.Create(new SignHashRequestDto
                    {
                        Username = _configuration.Username,
                        Password = _configuration.Password,
                        Hash =Convert.ToBase64String(hash),
                        HashAlgorithm = hashAlgorithm.Name!,
                        PaddingMode = padding.Mode
                    })
                });

                using var stream = response.Content.ReadAsStream();
                var responseDto = System.Text.Json.JsonSerializer.Deserialize<SignHashResponseDto>(stream);

                if (!string.IsNullOrEmpty(responseDto?.ErrorMessage))
                {
                    throw new CryptographicException(responseDto.ErrorMessage);
                }

                return Convert.FromBase64String(responseDto!.Signature);
            }
            catch (Exception e)
            {
                throw new CryptographicException("Error calling SigningServer", e);
            }
        }

        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm,
            RSASignaturePadding padding)
        {
            return _publicKey.VerifyHash(hash, signature, hashAlgorithm, padding);
        }


        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            using var hash = CreateHash(hashAlgorithm);
            return hash.ComputeHash(data, offset, count);
        }


        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            using var hash = CreateHash(hashAlgorithm);
            return hash.ComputeHash(data);
        }
    }

    private static HashAlgorithm CreateHash(HashAlgorithmName algorithm)
    {
        if (algorithm == HashAlgorithmName.SHA1)
            return SHA1.Create();

        if (algorithm == HashAlgorithmName.SHA256)
            return SHA256.Create();

        if (algorithm == HashAlgorithmName.SHA384)
            return SHA384.Create();

        if (algorithm == HashAlgorithmName.SHA512)
            return SHA512.Create();

        throw new NotSupportedException("The specified algorithm is not supported.");
    }
}
