using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using SigningServer.Server.Util;

namespace SigningServer.Server.Configuration;

/// <summary>
/// Represents the settings to load a certificate from the Windows Certificate Store.
/// </summary>
public class LocalStoreCertificateConfiguration
{
    /// <summary>
    /// The name of the certificate store to access (AddressBook, AuthRoot, CertificateAuthority, Disallowed, My, Root, TrustedPeople, TrustedPublisher)
    /// </summary>
    public string StoreName { get; set; }

    /// <summary>
    /// The location of the store (CurrentUser, LocalMachine)
    /// </summary>
    public string StoreLocation { get; set; }

    /// <summary>
    /// The thumbprint of the certificate to load
    /// </summary>
    public string Thumbprint { get; set; }

    /// <summary>
    /// The pin to unlock the hardware token (holding EV certificates)
    /// </summary>
    /// <remarks>
    /// The pin is encrypted, obtain the value to put here with 
    /// SigningServer.exe -encode TokenPinHere
    /// is is protected with the Windows DPAPI
    /// </remarks>
    public string TokenPin { get; set; }

    public void Load(ILogger logger, CertificateConfiguration certificateConfiguration,
        HardwareCertificateUnlocker unlocker)
    {
        logger.LogInformation("Loading Certificate from local machine");
        if (!Enum.TryParse(StoreName, out StoreName storeName))
        {
            throw new FormatException($"Invalid Store Name '{StoreName}' in configuration");
        }

        if (!Enum.TryParse(StoreLocation, out StoreLocation storeLocation))
        {
            throw new FormatException($"Invalid Store Location '{StoreLocation}' in configuration");
        }

        using var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadOnly);

        var certificates =
            store.Certificates
                .Where(c => Thumbprint.Equals(c.Thumbprint, StringComparison.InvariantCultureIgnoreCase))
                .ToArray();
        if (certificates.Length == 0)
        {
            throw new CryptographicException($"No certificate with the thumbprint '{Thumbprint}' found");
        }

        var certificate = certificates.FirstOrDefault(c => c.HasPrivateKey);

        certificateConfiguration.Certificate = certificate ?? throw new CryptographicException(
            $"Certificate with thumbprint '{Thumbprint}' has no private key");

        certificateConfiguration.PrivateKey = certificate.GetECDsaPrivateKey() ??
                     certificate.GetRSAPrivateKey() ??
                     (AsymmetricAlgorithm)certificate.GetDSAPrivateKey();

        var rsa = certificateConfiguration.Certificate.GetRSAPrivateKey();
        switch (rsa)
        {
            // For SmartCards/Hardware dongles we create a new RSACryptoServiceProvider with the corresponding pin
            case RSACryptoServiceProvider rsaCsp when !string.IsNullOrEmpty(TokenPin):
                {
                    logger.LogInformation("Patching RsaCsp for Hardware Token with pin");
                    var keyPassword = new SecureString();
                    var decrypted = DataProtector.UnprotectData(TokenPin);
                    foreach (var c in decrypted)
                    {
                        keyPassword.AppendChar(c);
                    }

                    var csp = new CspParameters(1 /*RSA*/,
                        rsaCsp.CspKeyContainerInfo.ProviderName,
                        rsaCsp.CspKeyContainerInfo.KeyContainerName) { KeyPassword = keyPassword };
                    csp.Flags |= CspProviderFlags.NoPrompt;

                    certificateConfiguration.PrivateKey = new RSACryptoServiceProvider(csp);
                    unlocker?.RegisterForUpdate(certificateConfiguration);
                    break;
                }
            // For normal Certs we patch the Hash Support if needed.
            case RSACryptoServiceProvider rsaCsp:
                {
                    certificateConfiguration.PrivateKey = PatchHashSupport(logger, rsaCsp);
                    break;
                }
            case RSACng cng when !string.IsNullOrEmpty(TokenPin):
                {
                    var decrypted = DataProtector.UnprotectData(TokenPin);
                    // https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers
                    // ReSharper disable once InconsistentNaming Win32 constant
                    const string NCRYPT_PIN_PROPERTY = "SmartCardPin";

                    // get bytes with null terminator
                    var propertyBytes = new byte[Encoding.Unicode.GetByteCount(decrypted) + 2];
                    Encoding.Unicode.GetBytes(decrypted, 0, decrypted.Length, propertyBytes, 0);
                    cng.Key.SetProperty(new CngProperty(
                        NCRYPT_PIN_PROPERTY,
                        propertyBytes,
                        CngPropertyOptions.None
                    ));
                    break;
                }
        }
    }

    public static RSACryptoServiceProvider PatchHashSupport(ILogger logger, RSACryptoServiceProvider orgKey)
    {
        var newKey = orgKey;
        try
        {
            // ReSharper disable once InconsistentNaming Win32 constant
            const int PROV_RSA_AES = 24; // CryptoApi provider type for an RSA provider supporting sha-256 digital signatures

            // ProviderType == 1(PROV_RSA_FULL) and providerType == 12(PROV_RSA_SCHANNEL) are provider types that only support SHA1.
            // Change them to PROV_RSA_AES=24 that supports SHA2 also. Only levels up if the associated key is not a hardware key.
            // Another provider type related to rsa, PROV_RSA_SIG == 2 that only supports Sha1 is no longer supported
            if (orgKey.CspKeyContainerInfo.ProviderType is 1 or 12 && !orgKey.CspKeyContainerInfo.HardwareDevice)
            {
                logger.LogInformation("Patching RsaCsp for Hash Support");

                var csp = new CspParameters
                {
                    ProviderType = PROV_RSA_AES,
                    KeyContainerName = orgKey.CspKeyContainerInfo.KeyContainerName,
                    KeyNumber = (int)orgKey.CspKeyContainerInfo.KeyNumber
                };

                if (orgKey.CspKeyContainerInfo.MachineKeyStore)
                {
                    csp.Flags = CspProviderFlags.UseMachineKeyStore;
                }

                //
                // If UseExistingKey is not specified, the CLR will generate a key for a non-existent group.
                // With this flag, a CryptographicException is thrown instead.
                //
                csp.Flags |= CspProviderFlags.UseExistingKey;
                return new RSACryptoServiceProvider(csp);
            }
            else
            {
                logger.LogInformation("Skipping RsaCsp Patching");
            }
        }
        finally
        {
            if (!ReferenceEquals(orgKey, newKey))
            {
                orgKey.Dispose();
            }
        }

        return newKey;
    }

    public override string ToString()
    {
        return $"Thumbprint={Thumbprint}";
    }
}
