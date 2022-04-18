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
/// An ActionResult implementation which sends a <see cref="SignFileResponse"/>
/// correctly to the client as multipart/form-data encoded response.
/// </summary>
public class SignFileActionResult : ActionResult, IStatusCodeActionResult
{
    private readonly IList<SignFileResponseFileInfo> _files;

    public int? StatusCode
    {
        get
        {
            return Response.Status switch
            {
                SignFileResponseStatus.FileSigned => StatusCodes.Status200OK,
                SignFileResponseStatus.FileResigned => StatusCodes.Status200OK,
                SignFileResponseStatus.FileAlreadySigned => StatusCodes.Status204NoContent,
                SignFileResponseStatus.FileNotSignedUnsupportedFormat => StatusCodes.Status400BadRequest,
                SignFileResponseStatus.FileNotSignedError => StatusCodes.Status500InternalServerError,
                SignFileResponseStatus.FileNotSignedUnauthorized => StatusCodes.Status401Unauthorized,
                _ => null
            };
        }
    }

    public Models.SignFileResponse Response { get; }

    public SignFileActionResult(Models.SignFileResponse apiSignFileResponse, IList<SignFileResponseFileInfo> files)
    {
        Response = apiSignFileResponse;
        _files = files;
    }

    public override async Task ExecuteResultAsync(ActionContext context)
    {
        var response = context.HttpContext.Response;
        var status = StatusCode;
        if (status.HasValue)
        {
            response.StatusCode = status.Value;
        }

        var boundary = Guid.NewGuid().ToString("N");
        response.ContentType = "multipart/form-data; boundary=" + boundary;
        
        var openedStreams = new Android.Collections.List<Stream>();
        try
        {
            var content = new MultipartFormDataContent(boundary);
         
            // Fill Base information
            content.Add(new StringContent(Response.Status.ToString()),
                nameof(Models.SignFileResponse.Status));
            if (!string.IsNullOrEmpty(Response.ErrorMessage))
            {
                content.Add(new StringContent(Response.ErrorMessage),
                    nameof(Models.SignFileResponse.ErrorMessage));
            }
            content.Add(new StringContent(Response.UploadTimeInMilliseconds.ToString()),
                nameof(Models.SignFileResponse.UploadTimeInMilliseconds));
            content.Add(new StringContent(Response.SignTimeInMilliseconds.ToString()),
                nameof(Models.SignFileResponse.SignTimeInMilliseconds));
            
            // Fill Files
            if (_files != null)
            {
                foreach (var file in _files)
                {
                    var stream = new FileStream(file.OutputFilePath, FileMode.Open, FileAccess.Read,
                        FileShare.Read | FileShare.Delete);
                    openedStreams.Add(stream);
                    content.Add(new StreamContent(stream, 1024 * 1024),
                        nameof(Models.SignFileResponse.ResultFiles),
                        file.FileName);
                }
            }
            
            // Stream to client
            await content.CopyToAsync(response.Body, context.HttpContext.RequestAborted);
        }
        catch (OperationCanceledException)
        {
            // Ignore cancellation
        }
        finally
        {
            foreach (var stream in openedStreams)
            {
                try
                {
                    await stream.DisposeAsync();
                }
                catch
                {
                    // ignore
                }
            }
        }
    }
}
