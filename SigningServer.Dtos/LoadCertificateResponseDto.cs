using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SigningServer.Core;

namespace SigningServer.Dtos;

/// <summary>
/// 
/// </summary>
/// <param name="Status">The result of the certificate loading</param>
/// <param name="ErrorMessage">The detailed error message in case <see cref="Status"/> is set to <see cref="LoadCertificateResponseStatus.CertificateNotLoadedError"/></param>
/// <param name="CertificateData"> The base64 encoded certificate bytes.</param>
public record LoadCertificateResponseDto(
    LoadCertificateResponseStatus Status,
    string? ErrorMessage,
    string? CertificateData
)
{
    public static byte[] Export(X509Certificate2Collection collection, LoadCertificateFormat exportFormat)
    {
        switch (exportFormat)
        {
            case LoadCertificateFormat.PemCertificate:
            case LoadCertificateFormat.PemPublicKey:
                {
                    using var ms = new MemoryStream();

                    for (var i = 0; i < collection.Count; i++)
                    {
                        if (i > 0)
                        {
                            ms.WriteByte((byte)'\n');
                        }

                        var cert = collection[i];
                        ms.Write(Export(cert, exportFormat));
                    }

                    return ms.ToArray();
                }
            case LoadCertificateFormat.Pkcs12:
                return collection.Export(X509ContentType.Pkcs12)!;
            default:
                throw new ArgumentOutOfRangeException(nameof(exportFormat), exportFormat, null);
        }
    }

    public static byte[] Export(X509Certificate2 certificate, LoadCertificateFormat exportFormat)
    {
        switch (exportFormat)
        {
            case LoadCertificateFormat.PemCertificate:
                var certificatePem = PemEncoding.Write("CERTIFICATE", certificate.RawData);
                return Encoding.ASCII.GetBytes(certificatePem);
            case LoadCertificateFormat.PemPublicKey:
                var key = (AsymmetricAlgorithm?)certificate.GetRSAPublicKey() ??
                          (AsymmetricAlgorithm?)certificate.GetDSAPublicKey() ??
                          certificate.GetECDsaPublicKey();
                var publicKeyPem = PemEncoding.Write("PUBLIC KEY", key!.ExportSubjectPublicKeyInfo());
                return Encoding.ASCII.GetBytes(publicKeyPem);
            case LoadCertificateFormat.Pkcs12:
                return certificate.Export(X509ContentType.Pkcs12);
            default:
                throw new ArgumentOutOfRangeException(nameof(exportFormat), exportFormat, null);
        }
    }

}
