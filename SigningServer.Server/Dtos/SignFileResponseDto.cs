using Microsoft.AspNetCore.Http;

namespace SigningServer.Server.Dtos;

public class SignFileResponseDto : SigningServer.Dtos.SignFileResponseDto
{
    /// <summary>
    /// The result files consisting typically of the signed file.
    /// In some scenarios additional files might be provided (e.g. Android v4 idsig)
    /// </summary>
    public IFormFileCollection? ResultFiles { get; set; } // Mainly used for documentation purposes, SignFileActionResult handles the serialization
}
