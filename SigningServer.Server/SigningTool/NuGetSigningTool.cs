using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NuGet.Common;
using NuGet.Packaging;
using NuGet.Packaging.Signing;
using SigningServer.Core;
using HashAlgorithmName = NuGet.Common.HashAlgorithmName;

namespace SigningServer.Server.SigningTool;

public class NuGetSigningTool : ISigningTool
{
    private static readonly HashSet<string> NuGetSupportedExtension =
        new(StringComparer.InvariantCultureIgnoreCase) { ".nupkg" };

    private static readonly Dictionary<string, HashAlgorithmName>
        NuGetSupportedHashAlgorithms =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ["SHA256"] = HashAlgorithmName.SHA256,
                ["SHA384"] = HashAlgorithmName.SHA384,
                ["SHA512"] = HashAlgorithmName.SHA512
            };

    private readonly ILogger<NuGetSigningTool> _logger;

    public string FormatName => "NuGet Packages";

    public NuGetSigningTool(ILogger<NuGetSigningTool> logger)
    {
        _logger = logger;
    }

    public bool IsFileSupported(string fileName)
    {
        return NuGetSupportedExtension.Contains(Path.GetExtension(fileName));
    }

    public async ValueTask<SignFileResponse> SignFileAsync(SignFileRequest signFileRequest,
        CancellationToken cancellationToken)
    {
        var signFileResponse = new SignFileResponse();
        var successResult = SignFileResponseStatus.FileSigned;

        if (await IsFileSignedAsync(signFileRequest.InputFilePath, cancellationToken))
        {
            if (signFileRequest.OverwriteSignature)
            {
                successResult = SignFileResponseStatus.FileResigned;
            }
            else
            {
                signFileResponse.Status = SignFileResponseStatus.FileAlreadySigned;
                return signFileResponse;
            }
        }

        var outputFile = Path.ChangeExtension(signFileRequest.InputFilePath, ".nupkg.signed");
        try
        {
            var timestampProvider = !string.IsNullOrEmpty(signFileRequest.TimestampServer)
                ? new Rfc3161TimestampProvider(new Uri(signFileRequest.TimestampServer))
                : null;
            var signatureProvider = new AsymmetricPrivateKeyX509SignatureProvider(signFileRequest.PrivateKey.Value,
                timestampProvider);
            using var options = SigningOptions.CreateFromFilePaths(
                signFileRequest.InputFilePath,
                outputFile,
                signFileRequest.OverwriteSignature,
                signatureProvider,
                new NuGetLogger(_logger));

            if (!NuGetSupportedHashAlgorithms.TryGetValue(signFileRequest.HashAlgorithm ?? "SHA256", out var hashAlg))
            {
                hashAlg = HashAlgorithmName.SHA256;
            }

            var request = new AuthorSignPackageRequest(signFileRequest.Certificate.Value, hashAlg);
            await SigningUtility.SignAsync(options, request, cancellationToken);
            signFileResponse.Status = successResult;
            signFileResponse.ResultFiles = new[]
            {
                new SignFileResponseFileInfo(signFileRequest.OriginalFileName, outputFile)
            };
            return signFileResponse;
        }
        catch
        {
            // ensure on error propagaion we delete intermediate output files which will not be reported.
            if (File.Exists(outputFile))
            {
                File.Delete(outputFile);
            }
            throw;
        }
    }

    internal class NuGetLogger : LoggerBase
    {
        private readonly ILogger<NuGetSigningTool> _logger;

        public NuGetLogger(ILogger<NuGetSigningTool> logger)
        {
            _logger = logger;
        }

        public override void Log(ILogMessage message)
        {
            _logger.Log(ConvertLevel(message.Level), message.Message);
        }

        private Microsoft.Extensions.Logging.LogLevel ConvertLevel(NuGet.Common.LogLevel messageLevel)
        {
            return messageLevel switch
            {
                NuGet.Common.LogLevel.Debug => Microsoft.Extensions.Logging.LogLevel.Debug,
                NuGet.Common.LogLevel.Verbose => Microsoft.Extensions.Logging.LogLevel.Trace,
                NuGet.Common.LogLevel.Information => Microsoft.Extensions.Logging.LogLevel.Information,
                NuGet.Common.LogLevel.Minimal => Microsoft.Extensions.Logging.LogLevel.Information,
                NuGet.Common.LogLevel.Warning => Microsoft.Extensions.Logging.LogLevel.Warning,
                NuGet.Common.LogLevel.Error => Microsoft.Extensions.Logging.LogLevel.Error,
                _ => throw new ArgumentOutOfRangeException(nameof(messageLevel))
            };
        }

        public override Task LogAsync(ILogMessage message)
        {
            Log(message);
            return Task.CompletedTask;
        }
    }


    public async ValueTask<bool> IsFileSignedAsync(string inputFileName, CancellationToken cancellationToken)
    {
        try
        {
            using var package = new PackageArchiveReader(inputFileName);
            return await package.IsSignedAsync(cancellationToken);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Could not load NuGet Package");
            return false;
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<string> SupportedFileExtensions => NuGetSupportedExtension.ToArray();

    public IReadOnlyList<string> SupportedHashAlgorithms => NuGetSupportedHashAlgorithms.Keys.ToArray();

    /// <summary>
    /// A <see cref="ISignatureProvider"/> implementation based on the original <see cref="X509SignatureProvider"/>
    /// allowing the usage of a generic <see cref="AsymmetricAlgorithm"/> instead of the <see cref="System.Security.Cryptography.CngKey"/>.
    /// </summary>
    private class AsymmetricPrivateKeyX509SignatureProvider : ISignatureProvider
    {
        private readonly AsymmetricAlgorithm _privateKey;
        private readonly ITimestampProvider _timestampProvider;

        public AsymmetricPrivateKeyX509SignatureProvider(AsymmetricAlgorithm privateKey,
            ITimestampProvider timestampProvider)
        {
            _privateKey = privateKey;
            _timestampProvider = timestampProvider;
        }

        public Task<PrimarySignature> CreatePrimarySignatureAsync(SignPackageRequest request,
            SignatureContent signatureContent, NuGet.Common.ILogger logger,
            CancellationToken token)
        {
            var signature = CreatePrimarySignature(request, signatureContent, logger);

            token.ThrowIfCancellationRequested();
            if (_timestampProvider == null)
            {
                return Task.FromResult(signature);
            }
            else
            {
                return TimestampPrimarySignatureAsync(request, logger, signature, token);
            }
        }

        public Task<PrimarySignature> CreateRepositoryCountersignatureAsync(RepositorySignPackageRequest request,
            PrimarySignature primarySignature,
            NuGet.Common.ILogger logger, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            var signature = CreateRepositoryCountersignature(request, primarySignature, logger);

            if (_timestampProvider == null)
            {
                return Task.FromResult(signature);
            }

            token.ThrowIfCancellationRequested();
            return TimestampRepositoryCountersignatureAsync(request, logger, signature, token);
        }

        private PrimarySignature CreateRepositoryCountersignature(SignPackageRequest request,
            PrimarySignature primarySignature, NuGet.Common.ILogger logger)
        {
            var cmsSigner = CreateCmsSigner(request, logger);

            var cms = new SignedCms();
            cms.Decode(primarySignature.GetBytes());

            cms.SignerInfos[0].ComputeCounterSignature(cmsSigner);

            return PrimarySignature.Load(cms);
        }


        private PrimarySignature CreatePrimarySignature(SignPackageRequest request,
            SignatureContent signatureContent, NuGet.Common.ILogger logger)
        {
            var cmsSigner = CreateCmsSigner(request, logger);

            var signingData = signatureContent.GetBytes();
            var contentInfo = new ContentInfo(signingData);
            var cms = new SignedCms(contentInfo);

            cms.ComputeSignature(cmsSigner, true);

            return PrimarySignature.Load(cms);
        }

        private CmsSigner CreateCmsSigner(SignPackageRequest request, NuGet.Common.ILogger logger)
        {
            var cmsSigner = SigningUtility.CreateCmsSigner(request, logger);
            cmsSigner.PrivateKey = _privateKey;
            return cmsSigner;
        }

        private Task<PrimarySignature> TimestampPrimarySignatureAsync(SignPackageRequest request,
            NuGet.Common.ILogger logger,
            PrimarySignature signature, CancellationToken token)
        {
            var signatureValue = signature.GetSignatureValue();
            var messageHash = request.TimestampHashAlgorithm.ComputeHash(signatureValue);

            var timestampRequest = new TimestampRequest(
                signingSpecifications: SigningSpecifications.V1,
                hashedMessage: messageHash,
                hashAlgorithm: request.TimestampHashAlgorithm,
                target: SignaturePlacement.PrimarySignature
            );

            return _timestampProvider.TimestampSignatureAsync(signature, timestampRequest, logger, token);
        }

        private Task<PrimarySignature> TimestampRepositoryCountersignatureAsync(SignPackageRequest request,
            NuGet.Common.ILogger logger, PrimarySignature primarySignature, CancellationToken token)
        {
            var repositoryCountersignature = RepositoryCountersignature.GetRepositoryCountersignature(primarySignature);
            var signatureValue = repositoryCountersignature.GetSignatureValue();
            var messageHash = request.TimestampHashAlgorithm.ComputeHash(signatureValue);

            var timestampRequest = new TimestampRequest(
                signingSpecifications: SigningSpecifications.V1,
                hashedMessage: messageHash,
                hashAlgorithm: request.TimestampHashAlgorithm,
                target: SignaturePlacement.Countersignature
            );

            return _timestampProvider.TimestampSignatureAsync(primarySignature, timestampRequest, logger, token);
        }
    }
}
