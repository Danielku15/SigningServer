using System;
using System.Collections.Generic;
using System.Text;

namespace SigningServer.Core;

/// <summary>
/// Describes the result of a signing operation.
/// </summary>
/// <param name="Status">The result status of the signing</param>
/// <param name="ErrorMessage"> The detailed error message in case <see cref="Status"/> is set to <see cref="SignFileResponseStatus.FileNotSignedError"/></param>
/// <param name="ResultFiles">
/// The result files consisting typically of the signed file.
/// In some scenarios additional files might be provided (e.g. Android v4 idsig)
/// </param>
public record SignFileResponse(
    SignFileResponseStatus Status,
    string ErrorMessage,
    IList<SignFileResponseFileInfo>? ResultFiles
)
{
    public static SignFileResponse FileAlreadySignedError = new(SignFileResponseStatus.FileAlreadySigned,
        "There is already a signature on the file and overwriting was disabled.",
        null);
}
