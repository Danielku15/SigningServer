namespace SigningServer.Server.Configuration;

/// <summary>
/// The overall signing server configuration
/// </summary>
public class SigningServerConfiguration
{
    public int HardwareCertificateUnlockIntervalInSeconds { get; set; }

    /// <summary>
    /// A RFC-3161 compliant timestamping server which should be used.
    /// </summary>
    public string TimestampServer { get; set; }

    /// <summary>
    /// A fallback Authenticode timestamping server for SHA1 based signing.
    /// </summary>
    public string Sha1TimestampServer { get; set; }

    /// <summary>
    /// The directory where the server will put temporarily the files during signing.
    /// </summary>
    public string WorkingDirectory { get; set; }

    public CertificateConfiguration[] Certificates { get; set; }

    /// <summary>
    /// The maximum degree of parallelism allowed per individual client.
    /// </summary>
    public int MaxDegreeOfParallelismPerClient { get; set; } = 4;
}
