using System.Collections.Generic;

namespace SigningServer.Core;

/// <summary>
/// A SigningTool is a component which can perform code signing
/// for one or more file formats.
/// </summary>
public interface ISigningTool
{
    /// <summary>
    /// Gets the name of the format the signing tool offers to sign.
    /// </summary>
    string FormatName { get; }

    /// <summary>
    /// Gets the list of file extensions handled by this signing tool.
    /// </summary>
    IReadOnlyList<string> SupportedFileExtensions { get; }

    /// <summary>
    /// Gets the list of hash algorithms supported by this signing tool.
    /// </summary>
    IReadOnlyList<string> SupportedHashAlgorithms { get; }

    /// <summary>
    /// Checks whether the file with the given name is supported.
    /// </summary>
    /// <param name="fileName">The name of the file</param>
    /// <returns>true if the signing tool supports the file, otherwise false.</returns>
    bool IsFileSupported(string fileName);

    /// <summary>
    /// Performs the signing of the given file through the request.
    /// Might throw any exceptions describing the error during signing.
    /// </summary>
    /// <param name="signFileRequest">The request describing what to sign.</param>
    /// <returns>The result of the signing operation.</returns>
    SignFileResponse SignFile(SignFileRequest signFileRequest);

    /// <summary>
    /// Checks whether the given file is signed.
    /// </summary>
    /// <param name="inputFileName">The path to the file on disk.</param>
    /// <returns>true if the file is considered signed, otherwise false.</returns>
    /// <remarks>
    /// Some tools might only do a very basic check and not a full validation on whether
    /// all aspects of the signing are in place and valid.
    /// </remarks>
    bool IsFileSigned(string inputFileName);
}
