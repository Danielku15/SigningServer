using System.Collections.Generic;

namespace SigningServer.Core;

/// <summary>
/// Represents a format the server supports.
/// </summary>
/// <param name="Name">The name of the format.</param>
/// <param name="SupportedFileExtensions">The supported file extensions of this format.</param>
/// <param name="SupportedHashAlgorithms">The supported hash algorithms of this format.</param>
public record ServerSupportedFormat(string Name,
    IReadOnlyList<string> SupportedFileExtensions,
    IReadOnlyList<string> SupportedHashAlgorithms
);
