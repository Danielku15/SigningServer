namespace SigningServer.Core;

/// <summary>
/// Describes a single output file of a signing operation.
/// </summary>
/// <param name="FileName">The name of the output file as it should be named on the client side.</param>
/// <param name="OutputFilePath">The full path to the disk holding the output file which should be sent to the client.</param>
public record SignFileResponseFileInfo(
    string FileName,
    string OutputFilePath);
