using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Moq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Core;
using SigningServer.Server.Configuration;
using SigningServer.Server.Controllers;
using SigningServer.Server.SigningTool;
using SignFileRequest = SigningServer.Server.Models.SignFileRequest;

namespace SigningServer.Test;

[TestClass]
public class SigningControllerSigningTest : UnitTestBase
{
    private static SigningServerConfiguration _configuration;
    private static ISigningToolProvider _emptySigningToolProvider;
    private static ISigningToolProvider _simultateSigningToolProvider;

    [ClassInitialize]
    public static void Setup(TestContext _)
    {
        _configuration = new SigningServerConfiguration
        {
            Certificates =
                new[]
                {
                    new CertificateConfiguration
                    {
                        Certificate = AssemblyEvents.Certificate, PrivateKey = AssemblyEvents.PrivateKey
                    }
                },
            WorkingDirectory = "WorkingDirectory"
        };

        _emptySigningToolProvider = new EnumerableSigningToolProvider(new List<ISigningTool>());

        var simulateSigningTool = new Mock<ISigningTool>();
        simulateSigningTool.Setup(t => t.SupportedFileExtensions).Returns(new[] { "*" });
        simulateSigningTool.Setup(t => t.SupportedHashAlgorithms).Returns(new[] { "*" });
        simulateSigningTool.Setup(t => t.IsFileSigned(It.IsAny<string>())).Returns(true);
        simulateSigningTool.Setup(t => t.IsFileSupported(It.IsAny<string>())).Returns(true);
        simulateSigningTool.Setup(t => t.SignFile(It.IsAny<Core.SignFileRequest>()))
            .Returns(new SignFileResponse
            {
                Status = SignFileResponseStatus.FileSigned,
                ResultFiles = new List<SignFileResponseFileInfo> { new SignFileResponseFileInfo("output", "file") }
            });
        _simultateSigningToolProvider = new EnumerableSigningToolProvider(new[] { simulateSigningTool.Object });
    }

    [TestMethod]
    public async Task SignFile_EmptyFile_Fails()
    {
        var server = new SigningController(AssemblyEvents.LoggerProvider.CreateLogger<SigningController>(),
            _emptySigningToolProvider, _configuration)
        {
            ControllerContext = CreateEmptyControllerContext()
        };

        var request = new SignFileRequest
        {
            FileToSign = new FormFile(new MemoryStream(), 0, 0, "FileToSign", "file.txt")
        };
        var response = await server.SignFileAsync(request, CancellationToken.None);
        AssertionExtensions.Should(response.Response.Status).Be(SignFileResponseStatus.FileNotSignedError);

        request = new SignFileRequest { FileToSign = null };
        response = await server.SignFileAsync(request, CancellationToken.None);
        AssertionExtensions.Should(response.Response.Status).Be(SignFileResponseStatus.FileNotSignedError);
    }

    [TestMethod]
    public async Task SignFile_NoAnonymousSigning_Fails()
    {
        var configuration = new SigningServerConfiguration
        {
            Certificates = new[]
            {
                new CertificateConfiguration
                {
                    Username = "SignUser",
                    Password = "SignPass",
                    Certificate = AssemblyEvents.Certificate,
                    PrivateKey = AssemblyEvents.PrivateKey
                }
            },
            WorkingDirectory = "WorkingDirectory"
        };

        var server = new SigningController(AssemblyEvents.LoggerProvider.CreateLogger<SigningController>(),
            _emptySigningToolProvider, configuration)
        {
            ControllerContext = CreateEmptyControllerContext()
        };

        var testData =
            new MemoryStream(
                await File.ReadAllBytesAsync(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.exe")));
        var request = new SignFileRequest
        {
            FileToSign = new FormFile(testData, 0, testData.Length, "FileToSign", "unsigned.exe")
        };

        var response = await server.SignFileAsync(request, CancellationToken.None);
        AssertionExtensions.Should(response.Response.Status).Be(SignFileResponseStatus.FileNotSignedUnauthorized);
    }

    private static ControllerContext CreateEmptyControllerContext()
    {
        return new ControllerContext(new ActionContext(new DefaultHttpContext
        {
            Connection =
            {
                RemoteIpAddress = IPAddress.Loopback
            }
        }, new RouteData(), new ControllerActionDescriptor()));
    }

    [TestMethod]
    public async Task SignFile_UnsupportedFormat_Fails()
    {
        var server = new SigningController(AssemblyEvents.LoggerProvider.CreateLogger<SigningController>(),
            _emptySigningToolProvider, _configuration)
        {
            ControllerContext = CreateEmptyControllerContext()
        };

        var testData =
            new MemoryStream(
                await File.ReadAllBytesAsync(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.exe")));
        var request = new SignFileRequest
        {
            FileToSign = new FormFile(testData, 0, testData.Length, "FileToSign", "unsigned.exe")
        };

        var response = await server.SignFileAsync(request, CancellationToken.None);
        AssertionExtensions.Should(response.Response.Status).Be(SignFileResponseStatus.FileNotSignedUnsupportedFormat);
    }

    [TestMethod]
    public async Task SignFile_UploadsFileToWorkingDirectory()
    {
        var server = new SigningController(AssemblyEvents.LoggerProvider.CreateLogger<SigningController>(),
            _simultateSigningToolProvider, _configuration)
        {
            ControllerContext = CreateEmptyControllerContext()
        };

        var testData =
            new MemoryStream(
                await File.ReadAllBytesAsync(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.exe")));
        var request = new SignFileRequest
        {
            FileToSign = new FormFile(testData, 0, testData.Length, "FileToSign", "unsigned.exe")
        };

        var response = await server.SignFileAsync(request, CancellationToken.None);
        AssertionExtensions.Should(response.Response.Status).Be(SignFileResponseStatus.FileSigned);
        var files = Directory.GetFileSystemEntries(_configuration.WorkingDirectory).ToArray();
        files.Length.Should().Be(1);
    }
}
