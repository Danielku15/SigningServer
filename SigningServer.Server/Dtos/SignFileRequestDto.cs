using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

namespace SigningServer.Server.Dtos;

public class SignFileRequestDto : SigningServer.Dtos.SignFileRequestDto
{
    /// <summary>
    /// The individual file to sign.
    /// </summary>
    [Required]
    public IFormFile? FileToSign { get; set; }
}
