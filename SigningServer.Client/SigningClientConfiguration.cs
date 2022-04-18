using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace SigningServer.Client;

/// <summary>
/// Represents the signing client configuration.
/// </summary>
public class SigningClientConfiguration
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

    /// <summary>
    /// Whether to overwrite existing signatures or fail when signatures are present.
    /// </summary>
    public bool OverwriteSignatures { get; set; }

    /// <summary>
    /// Whether to ignore any existing signatures and not sign in this case.
    /// </summary>
    public bool IgnoreExistingSignatures { get; set; } = true;
    
    /// <summary>
    /// Whether to ignore unsupported file formats or whether to fail when encountering them. 
    /// </summary>
    public bool IgnoreUnsupportedFiles { get; set; } = true;
    
    /// <summary>
    /// The timeout of signing operations in seconds.
    /// </summary>
    public int Timeout { get; set; } = 60;
    
    /// <summary>
    /// The hash algorithm to use.
    /// </summary>
    public string HashAlgorithm { get; set; }
    
    /// <summary>
    /// The number of retries the client should perform before giving up failed sign operations.
    /// </summary>
    public int Retry { get; set; } = 3;

    /// <summary>
    /// The number of parallel signing operations to perform.
    /// </summary>
    public int? Parallel { get; set; } = 1;

    /// <summary>
    /// The sources (files and directories) to sign.
    /// </summary>
    [JsonIgnore]
    public IList<string> Sources { get; set; } = new List<string>();
}
