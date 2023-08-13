using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SigningServer.Core;

namespace SigningServer.MsSign;

public class PortableExecutableSigningTool : ISigningTool
{
    private static readonly HashSet<string> PeSupportedExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe",
            ".dll",
            ".sys",
            ".msi",
            ".cab",
            ".cat",
            ".ps1"
        };

    private static readonly Dictionary<string, (uint algId, string algOid, HashAlgorithmName algName)>
        PeSupportedHashAlgorithms =
            new(StringComparer
                .OrdinalIgnoreCase)
            {
                ["SHA1"] = (Win32.CALG_SHA1, Win32.OID_OIWSEC_SHA1, HashAlgorithmName.SHA1),
                ["MD5"] = (Win32.CALG_MD5, Win32.OID_RSA_MD5, HashAlgorithmName.MD5),
                ["SHA256"] = (Win32.CALG_SHA_256, Win32.OID_OIWSEC_SHA256, HashAlgorithmName.SHA256),
                ["SHA384"] = (Win32.CALG_SHA_384, Win32.OID_OIWSEC_SHA384, HashAlgorithmName.SHA384),
                ["SHA512"] = (Win32.CALG_SHA_512, Win32.OID_OIWSEC_SHA512, HashAlgorithmName.SHA512)
            };

    protected ILogger Logger { get; }

    public virtual string FormatName => "Windows Portable Executables (PE)";

    public virtual IReadOnlyList<string> SupportedFileExtensions => PeSupportedExtensions.ToArray();
    public virtual IReadOnlyList<string> SupportedHashAlgorithms => PeSupportedHashAlgorithms.Keys.ToArray();

    public PortableExecutableSigningTool(ILogger<PortableExecutableSigningTool> logger)
    {
        Logger = logger;
    }

    protected PortableExecutableSigningTool(ILogger logger)
    {
        Logger = logger;
    }

    public virtual bool IsFileSupported(string fileName)
    {
        return PeSupportedExtensions.Contains(Path.GetExtension(fileName));
    }

    public ValueTask<bool> IsFileSignedAsync(string inputFileName, CancellationToken cancellationToken)
    {
        using var winTrustFileInfo = new UnmanagedStruct<Win32.WINTRUST_FILE_INFO>(
            new Win32.WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<Win32.WINTRUST_FILE_INFO>(),
                pcwszFilePath = inputFileName,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            });
        var winTrustData = new Win32.WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<Win32.WINTRUST_DATA>(),
            pPolicyCallbackData = IntPtr.Zero,
            pSIPClientData = IntPtr.Zero,
            dwUIChoice = Win32.WinTrustDataUIChoice.None,
            fdwRevocationChecks = Win32.WinTrustDataRevocationChecks.None,
            dwUnionChoice = Win32.WinTrustDataUnionChoice.File,
            dwStateAction = Win32.WinTrustDataStateAction.Verify,
            hWVTStateData = IntPtr.Zero,
            pwszURLReference = IntPtr.Zero,
            dwUIContext = 0,
            union = { pFile = winTrustFileInfo.Pointer }
        };

        var actionId = new Guid(Win32.WINTRUST_ACTION_GENERIC_VERIFY_V2);
        var result = Win32.WinVerifyTrust(IntPtr.Zero, actionId, winTrustData);
        Logger.LogTrace($"WinVerifyTrust returned {result}");

        switch (result)
        {
            case Win32.WinVerifyTrustResult.Success:
                return ValueTask.FromResult(true);
            case Win32.WinVerifyTrustResult.FileNotSigned:
                var dwLastError = (uint)Marshal.GetLastWin32Error();
                switch (dwLastError)
                {
                    case (uint)Win32.WinVerifyTrustResult.FileNotSigned:
                        return ValueTask.FromResult(false);
                    case (uint)Win32.WinVerifyTrustResult.SubjectFormUnknown:
                        return ValueTask.FromResult(true);
                    case (uint)Win32.WinVerifyTrustResult.ProviderUnknown:
                        return ValueTask.FromResult(true);
                    default:
                        return ValueTask.FromResult(false);
                }

            case Win32.WinVerifyTrustResult.UntrustedRoot:
                return ValueTask.FromResult(true);

            case Win32.WinVerifyTrustResult.SubjectExplicitlyDistrusted:
                return ValueTask.FromResult(true);

            case Win32.WinVerifyTrustResult.SubjectNotTrusted:
                return ValueTask.FromResult(true);

            case Win32.WinVerifyTrustResult.LocalSecurityOption:
                return ValueTask.FromResult(true);

            default:
                return ValueTask.FromResult(false);
        }
    }

    public async ValueTask<SignFileResponse> SignFileAsync(SignFileRequest signFileRequest,
        CancellationToken cancellationToken)
    {
        var successResult = SignFileResponseStatus.FileSigned;

        if (await IsFileSignedAsync(signFileRequest.InputFilePath, cancellationToken))
        {
            if (signFileRequest.OverwriteSignature)
            {
                Logger.LogTrace($"File {signFileRequest.InputFilePath} is already signed, removing signature");
                UnsignFile(signFileRequest.InputFilePath);
                successResult = SignFileResponseStatus.FileResigned;
            }
            else
            {
                Logger.LogTrace($"File {signFileRequest.InputFilePath} is already signed, abort signing");
                return SignFileResponse.FileAlreadySignedError;
            }
        }

        if (!PeSupportedHashAlgorithms.TryGetValue(
                signFileRequest.HashAlgorithm ?? "", out var algId))
        {
            algId = PeSupportedHashAlgorithms["SHA256"];
        }

        using var signerFileInfo = new UnmanagedStruct<Win32.SIGNER_FILE_INFO>(new Win32.SIGNER_FILE_INFO
        {
            cbSize = (uint)Marshal.SizeOf<Win32.SIGNER_FILE_INFO>(),
            pwszFileName = signFileRequest.InputFilePath,
            hFile = IntPtr.Zero
        });
        using var dwIndex = new UnmanagedStruct<uint>(0);
        using var signerSubjectInfo = new UnmanagedStruct<Win32.SIGNER_SUBJECT_INFO>(
            new Win32.SIGNER_SUBJECT_INFO
            {
                cbSize = (uint)Marshal.SizeOf<Win32.SIGNER_SUBJECT_INFO>(),
                pdwIndex = dwIndex.Pointer,
                dwSubjectChoice = Win32.SIGNER_SUBJECT_FILE,
                union = { pSignerFileInfo = signerFileInfo.Pointer }
            });
        using var signerCertStoreInfo = new UnmanagedStruct<Win32.SIGNER_CERT_STORE_INFO>(
            new Win32.SIGNER_CERT_STORE_INFO
            {
                cbSize = (uint)Marshal.SizeOf<Win32.SIGNER_CERT_STORE_INFO>(),
                pSigningCert = signFileRequest.Certificate.Value.Handle,
                dwCertPolicy = Win32.SIGNER_CERT_POLICY_CHAIN,
                hCertStore = IntPtr.Zero
            });
        using var signerCert = new UnmanagedStruct<Win32.SIGNER_CERT>(
            new Win32.SIGNER_CERT
            {
                cbSize = (uint)Marshal.SizeOf<Win32.SIGNER_CERT>(),
                dwCertChoice = Win32.SIGNER_CERT_STORE,
                union = { pSpcChainInfo = signerCertStoreInfo.Pointer },
                hwnd = IntPtr.Zero
            });
        using var signerSignatureInfo = new UnmanagedStruct<Win32.SIGNER_SIGNATURE_INFO>(
            new Win32.SIGNER_SIGNATURE_INFO
            {
                cbSize = (uint)Marshal.SizeOf<Win32.SIGNER_SIGNATURE_INFO>(),
                algidHash = algId.algId,
                dwAttrChoice = Win32.SIGNER_NO_ATTR,
                union = { pAttrAuthcode = IntPtr.Zero },
                psAuthenticated = IntPtr.Zero,
                psUnauthenticated = IntPtr.Zero
            });
        var (hr, tshr) = SignAndTimestamp(
            algId.algName,
            algId.algOid,
            signFileRequest.InputFilePath, signFileRequest.TimestampServer, signerSubjectInfo.Pointer,
            signerCert.Pointer,
            signerSignatureInfo.Pointer, signFileRequest.PrivateKey.Value
        );

        if (hr == Win32.S_OK && tshr == Win32.S_OK)
        {
            Logger.LogTrace($"{signFileRequest.InputFilePath} successfully signed");
            return new SignFileResponse(successResult, string.Empty,
                new[]
                {
                    new SignFileResponseFileInfo(signFileRequest.OriginalFileName, signFileRequest.InputFilePath)
                });
        }
        else if (hr != Win32.S_OK)
        {
            var exception = new Win32Exception(hr);
            var errorMessage = !string.IsNullOrEmpty(exception.Message)
                ? exception.Message
                : $"signing file failed (0x{hr:x})";

            if ((uint)hr == 0x8007000B)
            {
                errorMessage =
                    $"The appxmanifest does not contain the expected publisher. Expected: <Identity ... Publisher\"{signFileRequest.Certificate.Value.SubjectName}\" .. />.";
            }

            Logger.LogError($"{signFileRequest.InputFilePath} signing failed {errorMessage}");
            return new SignFileResponse(SignFileResponseStatus.FileNotSignedError, errorMessage, Array.Empty<SignFileResponseFileInfo>());
        }
        else
        {
            var errorText = new Win32Exception(tshr).Message;
            var errorMessage = !string.IsNullOrEmpty(errorText)
                ? errorText
                : $"timestamping failed (0x{hr:x})";
            

            Logger.LogError($"{signFileRequest.InputFilePath} timestamping failed {errorMessage}");
            return new SignFileResponse(SignFileResponseStatus.FileNotSignedError, errorMessage, Array.Empty<SignFileResponseFileInfo>());

        }
    }

    private protected virtual (int hr, int tshr) SignAndTimestamp(
        HashAlgorithmName hashAlgorithmName,
        string timestampHashOid,
        string inputFileName,
        string timestampServer,
        /*PSIGNER_SUBJECT_INFO*/IntPtr signerSubjectInfo,
        /*PSIGNER_CERT*/IntPtr signerCert,
        /*PSIGNER_SIGNATURE_INFO*/ IntPtr signerSignatureInfo,
        AsymmetricAlgorithm privateKey)
    {
        Logger.LogTrace($"Call signing of  {inputFileName}");

        int SignCallback(IntPtr pCertContext, IntPtr pvExtra, uint algId, byte[] pDigestToSign, uint dwDigestToSign,
            ref Win32.CRYPTOAPI_BLOB blob)
        {
            byte[] digest;
            try
            {
                switch (privateKey)
                {
                    case DSA dsa:
                        digest = dsa.CreateSignature(pDigestToSign);
                        break;
                    case ECDsa ecdsa:
                        digest = ecdsa.SignHash(pDigestToSign);
                        break;
                    case RSA rsa:
                        digest = rsa.SignHash(pDigestToSign, hashAlgorithmName, RSASignaturePadding.Pkcs1);
                        break;
                    default:
                        return Win32.E_INVALIDARG;
                }
            }
            catch (Exception e)
            {
                var hr = e.HResult != 0 ? e.HResult : Win32.NTE_BAD_KEY;
                Logger.LogError(e, "Failed to sign data reporting {hr}", hr);
                return hr;
            }

            var resultPtr = Marshal.AllocHGlobal(digest.Length);
            Marshal.Copy(digest, 0, resultPtr, digest.Length);
            blob.pbData = resultPtr;
            blob.cbData = (uint)digest.Length;
            return Win32.S_OK;
        }

        Win32.SignCallback callbackDelegate = SignCallback;

        using var unmanagedSignerParams = new UnmanagedStruct<Win32.SIGNER_SIGN_EX3_PARAMS>();
        using var unmanagedSignInfo = new UnmanagedStruct<Win32.SIGN_INFO>(new Win32.SIGN_INFO
        {
            cbSize = (uint)Marshal.SizeOf<Win32.SIGN_INFO>(),
            callback = Marshal.GetFunctionPointerForDelegate(callbackDelegate),
            pvOpaque = IntPtr.Zero
        });
        var signerParams = new Win32.SIGNER_SIGN_EX3_PARAMS
        {
            dwFlags = Win32.SIGN_CALLBACK_UNDOCUMENTED,
            pSubjectInfo = signerSubjectInfo,
            pSigningCert = signerCert,
            pSignatureInfo = signerSignatureInfo,
            pProviderInfo = IntPtr.Zero,
            psRequest = IntPtr.Zero,
            pCryptoPolicy = IntPtr.Zero,
            pSignCallback = unmanagedSignInfo.Pointer
        };
        unmanagedSignerParams.Fill(signerParams);

        var hr = Win32.SignerSignEx3(
            signerParams.dwFlags,
            signerParams.pSubjectInfo,
            signerParams.pSigningCert,
            signerParams.pSignatureInfo,
            signerParams.pProviderInfo,
            signerParams.dwTimestampFlags,
            signerParams.pszTimestampAlgorithmOid,
            signerParams.pwszTimestampURL,
            signerParams.psRequest,
            IntPtr.Zero,
            signerParams.pSignerContext,
            signerParams.pCryptoPolicy,
            signerParams.pSignCallback,
            signerParams.pReserved
        );

        if (signerParams.pSignerContext != IntPtr.Zero)
        {
            var signerContext = new IntPtr();
            Marshal.PtrToStructure(signerParams.pSignerContext, signerContext);
            Win32.SignerFreeSignerContext(signerContext);
        }

        var tshr = Win32.S_OK;
        if (hr == Win32.S_OK && !string.IsNullOrWhiteSpace(timestampServer))
        {
            Logger.LogTrace($"Timestamping with url {timestampServer}");
            var timestampRetries = 5;
            do
            {
                tshr = timestampHashOid == Win32.OID_OIWSEC_SHA1
                    ? Win32.SignerTimeStamp(signerSubjectInfo, timestampServer)
                    : Win32.SignerTimeStampEx2(
                        Win32.SIGNER_TIMESTAMP_RFC3161,
                        signerSubjectInfo,
                        timestampServer,
                        timestampHashOid,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero
                    );
                if (tshr == Win32.S_OK)
                {
                    Logger.LogTrace("Timestamping succeeded");
                }
                else
                {
                    Logger.LogTrace($"Timestamping failed with {tshr}, retries: {timestampRetries}");
                    Thread.Sleep(1000);
                }
            } while (tshr != Win32.S_OK && (timestampRetries--) > 0);
        }

        return (hr, tshr);
    }

    public virtual void UnsignFile(string fileName)
    {
        using var file = new FileStream(fileName, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
        // TODO: remove multiple certificates here?
        if (Win32.ImageEnumerateCertificates(file.SafeFileHandle, Win32.CERT_SECTION_TYPE_ANY,
                out var dwNumCerts) &&
            dwNumCerts == 1)
        {
            Win32.ImageRemoveCertificate(file.SafeFileHandle, 0);
        }
    }
}
