namespace SigningServer.Core;

/// <summary>
/// Lists all possible result status codes of a certificate loading operation.
/// </summary>
public enum LoadCertificateResponseStatus
{
    /// <summary>
    /// Certificate was successfully loaded
    /// </summary>
    CertificateLoaded,

    /// <summary>
    /// The certificate could not be loaded because an unexpected error happened.
    /// </summary>
    CertificateNotLoadedError,

    /// <summary>
    /// The certificate could not be loaded because the singing request was noth authorized.
    /// </summary>
    CertificateNotLoadedUnauthorized
}
