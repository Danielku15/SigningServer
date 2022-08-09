using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using SigningServer.Core;

namespace SigningServer.Server.Util;

/// <summary>
/// An ActionResult implementation which sends a <see cref="SignHashResponse"/>
/// correctly to the client as JSON encoded response with the right status value.
/// </summary>
public class SignHashActionResult : ObjectResult
{
    public SignHashActionResult(Dtos.SignHashResponseDto responseDto) : base(responseDto)
    {
        StatusCode = responseDto.Status switch
        {
            SignHashResponseStatus.HashSigned => StatusCodes.Status200OK,
            SignHashResponseStatus.HashNotSignedUnsupportedFormat => StatusCodes.Status400BadRequest,
            SignHashResponseStatus.HashNotSignedError => StatusCodes.Status500InternalServerError,
            SignHashResponseStatus.HashNotSignedUnauthorized => StatusCodes.Status401Unauthorized,
            _ => null
        };
    }
}
