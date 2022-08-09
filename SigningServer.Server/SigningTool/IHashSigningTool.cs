using System.Collections.Generic;
using SigningServer.Core;

namespace SigningServer.Server.SigningTool;

/// <summary>
/// Classes implementing this interface can sign hashes.
/// </summary>
public interface IHashSigningTool
{
    /// <summary>
    /// Performs the signing of the given hash through the request.
    /// Might throw any exceptions describing the error during signing.
    /// </summary>
    /// <param name="signHashRequest">The request describing what to sign.</param>
    /// <returns>The result of the signing operation.</returns>
    SignHashResponse SignHash(SignHashRequest signHashRequest);
}
