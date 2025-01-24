using System;
using SigningServer.Signing.Configuration;

namespace SigningServer.Server.Configuration;

/// <summary>
/// The overall signing server configuration
/// </summary>
public class SigningServerConfiguration
{
    public int HardwareCertificateUnlockIntervalInSeconds { get; set; }

    /// <summary>
    /// The interval how often the cached signing request audit information should be flushed to disk.
    /// </summary>
    public TimeSpan AuditFlushInterval { get; set; } = TimeSpan.FromMinutes(1);
    
    /// <summary>
    /// A RFC-3161 compliant timestamping server which should be used.
    /// </summary>
    public string TimestampServer { get; set; } = string.Empty;

    /// <summary>
    /// A fallback Authenticode timestamping server for SHA1 based signing.
    /// </summary>
    public string Sha1TimestampServer { get; set; } = string.Empty;

    /// <summary>
    /// The directory where the server will put temporarily the files during signing.
    /// </summary>
    public string WorkingDirectory { get; set; } = string.Empty;

    public CertificateConfiguration[] Certificates { get; set; } = Array.Empty<CertificateConfiguration>();
    public CertificateAccessCredentials[] AccessTokens { get; set; } = Array.Empty<CertificateAccessCredentials>();

    /// <summary>
    /// The maximum degree of parallelism allowed per individual client.
    /// </summary>
    public int MaxDegreeOfParallelismPerClient { get; set; } = 4;

    /// <summary>
    /// Whether the server should simply use one certificate handle for multiple signing requests or
    /// whether a pool of certificate handles should be used.
    ///
    /// This is useful for hardware certificates which may have a limited number of concurrent signing requests
    /// and where certificate handles might become invalid.
    /// </summary>
    public bool UseCertificatePooling { get; set; } = true;
}
