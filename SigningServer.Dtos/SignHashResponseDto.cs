using SigningServer.Core;

namespace SigningServer.Dtos;

/// <param name="Status">The result of the signing</param>
/// <param name="SignTimeInMilliseconds">The number of milliseconds it took to effectively sign the file.</param>
/// <param name="ErrorMessage"> The detailed error message in case <see cref="Status"/> is set to <see cref="SignHashResponseStatus.HashNotSignedError"/></param>
/// <param name="Signature">The hex encoded signature bytes of the signed hash.</param>
/// <param name="???"></param>
public record SignHashResponseDto(
    SignHashResponseStatus Status,
    long SignTimeInMilliseconds,
    string? ErrorMessage,
    string Signature
);
