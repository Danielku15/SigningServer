using System.Collections.Generic;

namespace SigningServer.Core;

/// <summary>
/// Lists all capabilities of the server. 
/// </summary>
/// <param name="MaxDegreeOfParallelismPerClient">The maximum level of parallelism allowed per client.</param>
/// <param name="SupportedFormats">The list of supported file formats.</param>
public record ServerCapabilitiesResponse(int MaxDegreeOfParallelismPerClient,
    IList<ServerSupportedFormat> SupportedFormats);
