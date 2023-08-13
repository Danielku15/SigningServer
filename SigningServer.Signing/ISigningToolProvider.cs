using System.Collections.Generic;
using SigningServer.Core;

namespace SigningServer.Signing;

/// <summary>
/// A provider of <see cref="ISigningTool"/> instances.
/// </summary>
public interface ISigningToolProvider
{
    /// <summary>
    /// Obtains the <see cref="ISigningTool"/> for the given file name.
    /// </summary>
    /// <param name="fileName">The name of the file.</param>
    /// <returns>The <see cref="ISigningTool"/> which can sign the given file.</returns>
    /// <remarks>
    /// Detection is typically done based on the file extension.
    /// </remarks>
    ISigningTool GetSigningTool(string fileName);

    /// <summary>
    /// A list of all <see cref="ISigningTool"/>s this provider has available.
    /// </summary>
    IList<ISigningTool> AllTools { get; }
}
