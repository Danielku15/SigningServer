using System.Collections.Generic;

namespace SigningServer.Core;

/// <summary>
/// Lists all capabilities of the server. 
/// </summary>
public class ServerCapabilitiesResponse
{
    /// <summary>
    /// The list of supported file formats.
    /// </summary>
    public IList<ServerSupportedFormat> SupportedFormats { get; set; }
}
