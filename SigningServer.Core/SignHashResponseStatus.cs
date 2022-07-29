namespace SigningServer.Core;

/// <summary>
/// Lists all possible result status codes of a hash signing operation.
/// </summary>
public enum SignHashResponseStatus
{
    /// <summary>
    /// Hash was successfully signed
    /// </summary>
    HashSigned,

    /// <summary>
    /// The hash was not signed because the given hash algorithm/format is not supported.
    /// </summary>
    HashNotSignedUnsupportedFormat,

    /// <summary>
    /// The hash was not signed because an unexpected error happened.
    /// </summary>
    HashNotSignedError,

    /// <summary>
    /// The hash was not signed because the singing request was noth authorized.
    /// </summary>
    HashNotSignedUnauthorized
}
