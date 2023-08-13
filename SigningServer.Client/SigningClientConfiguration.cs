using System.Collections.Generic;
using System.Text.Json.Serialization;
using SigningServer.ClientCore;
using SigningServer.Core;

namespace SigningServer.Client;

/// <summary>
/// Represents the signing client configuration.
/// </summary>
public class SigningClientConfiguration : SigningClientConfigurationBase
{
    /// <summary>
    /// The url to the signing server.
    /// </summary>
    public string SigningServer { get; set; }

    /// <summary>
    /// The username for authentication and cerificate selection.
    /// </summary>
    public string Username { get; set; }

    /// <summary>
    /// The password for authentication and certificate selection.
    /// </summary>
    public string Password { get; set; }
}
