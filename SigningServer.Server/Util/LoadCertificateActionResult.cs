using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SigningServer.Core;
using SigningServer.Dtos;

namespace SigningServer.Server.Util;

/// <summary>
/// An ActionResult implementation which sends a <see cref="LoadCertificateResponseDto"/>
/// correctly to the client as JSON encoded response with the right status value.
/// </summary>
public class LoadCertificateActionResult : ObjectResult
{
    public LoadCertificateActionResult(LoadCertificateResponseDto responseDto) : base(responseDto)
    {
        StatusCode = responseDto.Status switch
        {
            LoadCertificateResponseStatus.CertificateLoaded => StatusCodes.Status200OK,
            LoadCertificateResponseStatus.CertificateNotLoadedError => StatusCodes.Status500InternalServerError,
            LoadCertificateResponseStatus.CertificateNotLoadedUnauthorized => StatusCodes.Status401Unauthorized,
            _ => null
        };
    }
}
