using System.Collections.Generic;

namespace SigningServer.Core;

/// <summary>
/// Represents a format the server supports.
/// </summary>
public class ServerSupportedFormat
{
    /// <summary>
    /// The name of the format.
    /// </summary>
    public string Name { get; set; }
    
    /// <summary>
    /// The supported file extensions of this format.
    /// </summary>
    public IList<string> SupportedFileExtensions { get; set; }
    
    /// <summary>
    /// The supported hash algorithms of this format.
    /// </summary>
    public IList<string> SupportedHashAlgorithms { get; set; }
}
