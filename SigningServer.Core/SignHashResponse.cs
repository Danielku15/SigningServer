namespace SigningServer.Core;

/// <summary>
/// Describes the result of a hash signing operation.
/// </summary>
/// <param name="Status">The result status of the signing.</param>
/// <param name="ErrorMessage">The detailed error message in case <see cref="Status"/> is set to <see cref="SignHashResponseStatus.HashNotSignedError"/></param>
/// <param name="Signature">The resulting signature of the provided hash.</param>
public record SignHashResponse(
    SignHashResponseStatus Status,
    string ErrorMessage,
    byte[] Signature
);
