using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Microsoft.Extensions.Logging;
using SigningServer.Contracts;

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
                ["SHA512"] = (Win32.CALG_SHA_512, Win32.OID_OIWSEC_SHA512, HashAlgorithmName.SHA512),
            };

    private readonly ILogger _logger;

    public virtual string[] SupportedFileExtensions => PeSupportedExtensions.ToArray();
    public virtual string[] SupportedHashAlgorithms => PeSupportedHashAlgorithms.Keys.ToArray();

    public PortableExecutableSigningTool(ILogger<PortableExecutableSigningTool> logger)
    {
        _logger = logger;
    }

    protected PortableExecutableSigningTool(ILogger logger)
    {
        _logger = logger;
    }

    public virtual bool IsFileSupported(string fileName)
    {
        return PeSupportedExtensions.Contains(Path.GetExtension(fileName));
    }

    public bool IsFileSigned(string inputFileName)
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
        _logger.LogTrace($"WinVerifyTrust returned {result}");

        switch (result)
        {
            case Win32.WinVerifyTrustResult.Success:
                return true;
            case Win32.WinVerifyTrustResult.FileNotSigned:
                var dwLastError = (uint)Marshal.GetLastWin32Error();
                switch (dwLastError)
                {
                    case (uint)Win32.WinVerifyTrustResult.FileNotSigned:
                        return false;
                    case (uint)Win32.WinVerifyTrustResult.SubjectFormUnknown:
                        return true;
                    case (uint)Win32.WinVerifyTrustResult.ProviderUnknown:
                        return true;
                    default:
                        return false;
                }

            case Win32.WinVerifyTrustResult.UntrustedRoot:
                return true;

            case Win32.WinVerifyTrustResult.SubjectExplicitlyDistrusted:
                return true;

            case Win32.WinVerifyTrustResult.SubjectNotTrusted:
                return true;

            case Win32.WinVerifyTrustResult.LocalSecurityOption:
                return true;

            default:
                return false;
        }
    }

    public void SignFile(string inputFileName, X509Certificate2 certificate,
        AsymmetricAlgorithm privateKey,
        string timestampServer,
        SignFileRequest signFileRequest, SignFileResponse signFileResponse)
    {
        var successResult = SignFileResponseResult.FileSigned;

        if (IsFileSigned(inputFileName))
        {
            if (signFileRequest.OverwriteSignature)
            {
                _logger.LogTrace($"File {inputFileName} is already signed, removing signature");
                UnsignFile(inputFileName);
                successResult = SignFileResponseResult.FileResigned;
            }
            else
            {
                _logger.LogTrace($"File {inputFileName} is already signed, abort signing");
                signFileResponse.Result = SignFileResponseResult.FileAlreadySigned;
                return;
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
            pwszFileName = inputFileName,
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
                pSigningCert = certificate.Handle,
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
            inputFileName, timestampServer, signerSubjectInfo.Pointer,
            signerCert.Pointer,
            signerSignatureInfo.Pointer, privateKey
        );

        if (hr == Win32.S_OK && tshr == Win32.S_OK)
        {
            _logger.LogTrace($"{inputFileName} successfully signed");
            signFileResponse.Result = successResult;
            signFileResponse.FileContent = new FileStream(inputFileName,
                FileMode.Open,
                FileAccess.Read);
            signFileResponse.FileSize = signFileResponse.FileContent.Length;
        }
        else if (hr != Win32.S_OK)
        {
            var exception = new Win32Exception(hr);
            signFileResponse.Result = SignFileResponseResult.FileNotSignedError;
            signFileResponse.ErrorMessage = !string.IsNullOrEmpty(exception.Message)
                ? exception.Message
                : $"signing file failed (0x{hr:x})";

            if ((uint)hr == 0x8007000B)
            {
                signFileResponse.ErrorMessage =
                    $"The appxmanifest does not contain the expected publisher. Expected: <Identity ... Publisher\"{certificate.SubjectName}\" .. />.";
            }

            _logger.LogError($"{inputFileName} signing failed {signFileResponse.ErrorMessage}");
        }
        else
        {
            var errorText = new Win32Exception(tshr).Message;
            signFileResponse.Result = SignFileResponseResult.FileNotSignedError;
            signFileResponse.ErrorMessage = !string.IsNullOrEmpty(errorText)
                ? errorText
                : $"timestamping failed (0x{hr:x})";

            _logger.LogError($"{inputFileName} timestamping failed {signFileResponse.ErrorMessage}");
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
        _logger.LogTrace($"Call signing of  {inputFileName}");

        int SignCallback(IntPtr pCertContext, IntPtr pvExtra, uint algId, byte[] pDigestToSign, uint dwDigestToSign,
            ref Win32.CRYPTOAPI_BLOB blob)
        {
            byte[] digest;
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

            var resultPtr = Marshal.AllocHGlobal(digest.Length);
            Marshal.Copy(digest, 0, resultPtr, digest.Length);
            blob.pbData = resultPtr;
            blob.cbData = (uint)digest.Length;
            return 0;
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
            _logger.LogTrace($"Timestamping with url {timestampServer}");
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
                    _logger.LogTrace("Timestamping succeeded");
                }
                else
                {
                    _logger.LogTrace($"Timestamping failed with {tshr}, retries: {timestampRetries}");
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