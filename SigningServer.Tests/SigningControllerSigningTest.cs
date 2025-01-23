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
using NUnit.Framework;
using SigningServer.Core;
using SigningServer.Server;
using SigningServer.Server.Configuration;
using SigningServer.Server.Controllers;
using SigningServer.Server.Dtos;
using SigningServer.Signing;
using SigningServer.Signing.Configuration;
using SignFileResponse = SigningServer.Core.SignFileResponse;

namespace SigningServer.Test;

public class SigningControllerSigningTest : UnitTestBase
{
    private SigningServerConfiguration _configuration = null!;
    private ISigningToolProvider _emptySigningToolProvider = null!;
    private ISigningToolProvider _simulateSigningToolProvider = null!;

    [OneTimeSetUp]
    public async Task Setup()
    {
        _configuration = new SigningServerConfiguration
        {
            Certificates =
                new[]
                {
                    new CertificateConfiguration
                    {
                        Certificate = await AssemblyEvents.Certificate.Value,
                        PrivateKey = await AssemblyEvents.PrivateKey.Value
                    }
                },
            WorkingDirectory = "WorkingDirectory"
        };

        _emptySigningToolProvider = new EnumerableSigningToolProvider(new List<ISigningTool>());

        var simulateSigningTool = new Mock<ISigningTool>();
        simulateSigningTool.Setup(t => t.SupportedFileExtensions).Returns(new[] { "*" });
        simulateSigningTool.Setup(t => t.SupportedHashAlgorithms).Returns(new[] { "*" });
        simulateSigningTool.Setup(t => t.IsFileSignedAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(ValueTask.FromResult(true));
        simulateSigningTool.Setup(t => t.IsFileSupported(It.IsAny<string>())).Returns(true);
        simulateSigningTool.Setup(t => t.SignFileAsync(It.IsAny<SignFileRequest>(), It.IsAny<CancellationToken>()))
            .Returns(ValueTask.FromResult(new SignFileResponse(SignFileResponseStatus.FileSigned,
                string.Empty,
                new[] { new SignFileResponseFileInfo("output", "file") }
            )));
        _simulateSigningToolProvider = new EnumerableSigningToolProvider(new[] { simulateSigningTool.Object });
    }

    [Test]
    public async Task SignFile_EmptyFile_Fails()
    {
        var server = new SigningController(AssemblyEvents.LoggerProvider.CreateLogger<SigningController>(),
            _emptySigningToolProvider, null!, _configuration, new NonPooledCertificateProvider(_configuration),
            new TestingSigningRequestTracker()) { ControllerContext = CreateEmptyControllerContext() };

        var request = new SignFileRequestDto
        {
            FileToSign = new FormFile(new MemoryStream(), 0, 0, "FileToSign", "file.txt")
        };
        var response = await server.SignFileAsync(request, CancellationToken.None);
        response.ResponseDto.Status.Should().Be(SignFileResponseStatus.FileNotSignedError);

        request = new SignFileRequestDto { FileToSign = null };
        response = await server.SignFileAsync(request, CancellationToken.None);
        response.ResponseDto.Status.Should().Be(SignFileResponseStatus.FileNotSignedError);
    }

    [Test]
    public async Task SignFile_NoAnonymousSigning_Fails()
    {
        var configuration = new SigningServerConfiguration
        {
            Certificates = new[]
            {
                new CertificateConfiguration
                {
                    Credentials =
                        new[]
                        {
                            new CertificateAccessCredentials
                            {
                                Username = "SignUser", Password = "SignPass",
                            }
                        },
                    Certificate = await AssemblyEvents.Certificate.Value,
                    PrivateKey = await AssemblyEvents.PrivateKey.Value
                }
            },
            WorkingDirectory = "WorkingDirectory"
        };

        var server = new SigningController(AssemblyEvents.LoggerProvider.CreateLogger<SigningController>(),
            _emptySigningToolProvider, null!, configuration, new NonPooledCertificateProvider(configuration),
            new TestingSigningRequestTracker()) { ControllerContext = CreateEmptyControllerContext() };

        var testData =
            new MemoryStream(
                await File.ReadAllBytesAsync(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.exe")));
        var request = new SignFileRequestDto
        {
            FileToSign = new FormFile(testData, 0, testData.Length, "FileToSign", "unsigned.exe")
        };

        var response = await server.SignFileAsync(request, CancellationToken.None);
        response.ResponseDto.Status.Should().Be(SignFileResponseStatus.FileNotSignedUnauthorized);
    }

    private static ControllerContext CreateEmptyControllerContext()
    {
        return new ControllerContext(new ActionContext(
            new DefaultHttpContext { Connection = { RemoteIpAddress = IPAddress.Loopback } }, new RouteData(),
            new ControllerActionDescriptor()));
    }

    [Test]
    public async Task SignFile_UnsupportedFormat_Fails()
    {
        var server = new SigningController(AssemblyEvents.LoggerProvider.CreateLogger<SigningController>(),
            _emptySigningToolProvider, null!, _configuration, new NonPooledCertificateProvider(_configuration),
            new TestingSigningRequestTracker()) { ControllerContext = CreateEmptyControllerContext() };

        var testData =
            new MemoryStream(
                await File.ReadAllBytesAsync(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.exe")));
        var request = new SignFileRequestDto
        {
            FileToSign = new FormFile(testData, 0, testData.Length, "FileToSign", "unsigned.exe")
        };

        var response = await server.SignFileAsync(request, CancellationToken.None);
        response.ResponseDto.Status.Should().Be(SignFileResponseStatus.FileNotSignedUnsupportedFormat);
    }

    [Test]
    public async Task SignFile_UploadsFileToWorkingDirectory()
    {
        var server = new SigningController(AssemblyEvents.LoggerProvider.CreateLogger<SigningController>(),
            _simulateSigningToolProvider, null!, _configuration, new NonPooledCertificateProvider(_configuration),
            new TestingSigningRequestTracker()) { ControllerContext = CreateEmptyControllerContext() };

        var testData =
            new MemoryStream(
                await File.ReadAllBytesAsync(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.exe")));
        var request = new SignFileRequestDto
        {
            FileToSign = new FormFile(testData, 0, testData.Length, "FileToSign", "unsigned.exe")
        };

        var response = await server.SignFileAsync(request, CancellationToken.None);
        response.ResponseDto.Status.Should().Be(SignFileResponseStatus.FileSigned);
        var files = Directory.GetFileSystemEntries(_configuration.WorkingDirectory).ToArray();
        files.Length.Should().Be(1);
    }
}
