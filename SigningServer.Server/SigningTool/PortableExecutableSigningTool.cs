using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using NLog;
using SigningServer.Contracts;

namespace SigningServer.Server.SigningTool
{
    public class PortableExecutableSigningTool : ISigningTool
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();


        private static readonly HashSet<string> PeSupportedExtensions =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".exe", ".dll", ".sys", ".msi", ".cab", ".cat"
            };

        private static readonly Dictionary<string, (uint algId, string algOid, HashAlgorithmName algName)>
            PeSupportedHashAlgorithms =
                new Dictionary<string, (uint algId, string algOid, HashAlgorithmName algName)>(StringComparer
                    .OrdinalIgnoreCase)
                {
                    ["SHA1"] = (MsSign32.CALG_SHA1, MsSign32.OID_OIWSEC_SHA1, HashAlgorithmName.SHA1),
                    ["MD5"] = (MsSign32.CALG_MD5, MsSign32.OID_RSA_MD5, HashAlgorithmName.MD5),
                    ["SHA256"] = (MsSign32.CALG_SHA_256, MsSign32.OID_OIWSEC_SHA256, HashAlgorithmName.SHA256),
                    ["SHA384"] = (MsSign32.CALG_SHA_384, MsSign32.OID_OIWSEC_SHA384, HashAlgorithmName.SHA384),
                    ["SHA512"] = (MsSign32.CALG_SHA_512, MsSign32.OID_OIWSEC_SHA512, HashAlgorithmName.SHA512),
                };

        public virtual string[] SupportedFileExtensions => PeSupportedExtensions.ToArray();
        public virtual string[] SupportedHashAlgorithms => PeSupportedHashAlgorithms.Keys.ToArray();

        public virtual bool IsFileSupported(string fileName)
        {
            return PeSupportedExtensions.Contains(Path.GetExtension(fileName));
        }

        public bool IsFileSigned(string inputFileName)
        {
            using (var winTrustFileInfo = new UnmanagedStruct<MsSign32.WINTRUST_FILE_INFO>(
                       new MsSign32.WINTRUST_FILE_INFO
                       {
                           cbStruct = (uint)Marshal.SizeOf<MsSign32.WINTRUST_FILE_INFO>(),
                           pcwszFilePath = inputFileName,
                           hFile = IntPtr.Zero,
                           pgKnownSubject = IntPtr.Zero
                       }))
            {
                var winTrustData = new MsSign32.WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<MsSign32.WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = MsSign32.WinTrustDataUIChoice.None,
                    fdwRevocationChecks = MsSign32.WinTrustDataRevocationChecks.None,
                    dwUnionChoice = MsSign32.WinTrustDataUnionChoice.File,
                    dwStateAction = MsSign32.WinTrustDataStateAction.Verify,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = IntPtr.Zero,
                    dwUIContext = 0,
                    union =
                    {
                        pFile = winTrustFileInfo.Pointer
                    }
                };

                var actionId = new Guid(MsSign32.WINTRUST_ACTION_GENERIC_VERIFY_V2);
                var result = MsSign32.WinVerifyTrust(IntPtr.Zero, actionId, winTrustData);
                Log.Trace($"WinVerifyTrust returned {result}");

                switch (result)
                {
                    case MsSign32.WinVerifyTrustResult.Success:
                        return true;
                    case MsSign32.WinVerifyTrustResult.FileNotSigned:
                        var dwLastError = (uint)Marshal.GetLastWin32Error();
                        switch (dwLastError)
                        {
                            case (uint)MsSign32.WinVerifyTrustResult.FileNotSigned:
                                return false;
                            case (uint)MsSign32.WinVerifyTrustResult.SubjectFormUnknown:
                                return true;
                            case (uint)MsSign32.WinVerifyTrustResult.ProviderUnknown:
                                return true;
                            default:
                                return false;
                        }

                    case MsSign32.WinVerifyTrustResult.UntrustedRoot:
                        return true;

                    case MsSign32.WinVerifyTrustResult.SubjectExplicitlyDistrusted:
                        return true;

                    case MsSign32.WinVerifyTrustResult.SubjectNotTrusted:
                        return true;

                    case MsSign32.WinVerifyTrustResult.LocalSecurityOption:
                        return true;

                    default:
                        return false;
                }
            }
        }

        public void SignFile(string inputFileName, X509Certificate2 certificate, string timestampServer,
            SignFileRequest signFileRequest, SignFileResponse signFileResponse)
        {
            var successResult = SignFileResponseResult.FileSigned;

            if (IsFileSigned(inputFileName))
            {
                if (signFileRequest.OverwriteSignature)
                {
                    Log.Trace($"File {inputFileName} is already signed, removing signature");
                    UnsignFile(inputFileName);
                    successResult = SignFileResponseResult.FileResigned;
                }
                else
                {
                    Log.Trace($"File {inputFileName} is already signed, abort signing");
                    signFileResponse.Result = SignFileResponseResult.FileAlreadySigned;
                    return;
                }
            }

            if (!PeSupportedHashAlgorithms.TryGetValue(
                    signFileRequest.HashAlgorithm ?? "", out var algId))
            {
                algId = PeSupportedHashAlgorithms["SHA256"];
            }

            // var cspParameters = GetPrivateKeyInfo(certificate);

            using (var signerFileInfo = new UnmanagedStruct<MsSign32.SIGNER_FILE_INFO>(new MsSign32.SIGNER_FILE_INFO
                   {
                       cbSize = (uint)Marshal.SizeOf<MsSign32.SIGNER_FILE_INFO>(),
                       pwszFileName = inputFileName,
                       hFile = IntPtr.Zero
                   }))
            using (var dwIndex = new UnmanagedStruct<uint>(0))
            using (var signerSubjectInfo = new UnmanagedStruct<MsSign32.SIGNER_SUBJECT_INFO>(
                       new MsSign32.SIGNER_SUBJECT_INFO
                       {
                           cbSize = (uint)Marshal.SizeOf<MsSign32.SIGNER_SUBJECT_INFO>(),
                           pdwIndex = dwIndex.Pointer,
                           dwSubjectChoice = MsSign32.SIGNER_SUBJECT_FILE,
                           union =
                           {
                               pSignerFileInfo = signerFileInfo.Pointer
                           }
                       }))
            using (var signerCertStoreInfo = new UnmanagedStruct<MsSign32.SIGNER_CERT_STORE_INFO>(
                       new MsSign32.SIGNER_CERT_STORE_INFO
                       {
                           cbSize = (uint)Marshal.SizeOf<MsSign32.SIGNER_CERT_STORE_INFO>(),
                           pSigningCert = certificate.Handle,
                           dwCertPolicy = MsSign32.SIGNER_CERT_POLICY_CHAIN,
                           hCertStore = IntPtr.Zero
                       }))
            using (var signerCert = new UnmanagedStruct<MsSign32.SIGNER_CERT>(
                       new MsSign32.SIGNER_CERT
                       {
                           cbSize = (uint)Marshal.SizeOf<MsSign32.SIGNER_CERT>(),
                           dwCertChoice = MsSign32.SIGNER_CERT_STORE,
                           union =
                           {
                               pSpcChainInfo = signerCertStoreInfo.Pointer
                           },
                           hwnd = IntPtr.Zero
                       }))
            using (var signerSignatureInfo = new UnmanagedStruct<MsSign32.SIGNER_SIGNATURE_INFO>(
                       new MsSign32.SIGNER_SIGNATURE_INFO
                       {
                           cbSize = (uint)Marshal.SizeOf<MsSign32.SIGNER_SIGNATURE_INFO>(),
                           algidHash = algId.algId,
                           dwAttrChoice = MsSign32.SIGNER_NO_ATTR,
                           union =
                           {
                               pAttrAuthcode = IntPtr.Zero
                           },
                           psAuthenticated = IntPtr.Zero,
                           psUnauthenticated = IntPtr.Zero
                       }))
            {
                var (hr, tshr) = SignAndTimestamp(
                    algId.algName,
                    algId.algOid,
                    inputFileName, timestampServer, signerSubjectInfo.Pointer,
                    signerCert.Pointer,
                    signerSignatureInfo.Pointer, certificate
                );

                if (hr == MsSign32.S_OK && tshr == MsSign32.S_OK)
                {
                    Log.Trace($"{inputFileName} successfully signed");
                    signFileResponse.Result = successResult;
                    signFileResponse.FileContent = new FileStream(inputFileName,
                        FileMode.Open,
                        FileAccess.Read);
                    signFileResponse.FileSize = signFileResponse.FileContent.Length;
                }
                else if (hr != MsSign32.S_OK)
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

                    Log.Error($"{inputFileName} signing failed {signFileResponse.ErrorMessage}");
                }
                else
                {
                    var errorText = new Win32Exception(tshr).Message;
                    signFileResponse.Result = SignFileResponseResult.FileNotSignedError;
                    signFileResponse.ErrorMessage = !string.IsNullOrEmpty(errorText)
                        ? errorText
                        : $"timestamping failed (0x{hr:x})";

                    Log.Error($"{inputFileName} timestamping failed {signFileResponse.ErrorMessage}");
                }
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
            X509Certificate2 certificate)
        {
            Log.Trace($"Call signing of  {inputFileName}");

            int SignCallback(IntPtr pCertContext, IntPtr pvExtra, uint algId, byte[] pDigestToSign, uint dwDigestToSign,
                ref MsSign32.CRYPTOAPI_BLOB blob)
            {
                byte[] digest;
                switch (certificate.PrivateKey)
                {
                    case RSA rsa:
                        digest = rsa.SignHash(pDigestToSign, hashAlgorithmName, RSASignaturePadding.Pkcs1);
                        break;
                    default:
                        return MsSign32.E_INVALIDARG;
                }

                var resultPtr = Marshal.AllocHGlobal(digest.Length);
                Marshal.Copy(digest, 0, resultPtr, digest.Length);
                blob.pbData = resultPtr;
                blob.cbData = (uint)digest.Length;
                return 0;
            }

            MsSign32.SignCallback callbackDelegate = SignCallback;

            using (var unmanagedSignerParams = new UnmanagedStruct<MsSign32.SIGNER_SIGN_EX3_PARAMS>())
            using (var unmanagedSignInfo = new UnmanagedStruct<MsSign32.SIGN_INFO>(new MsSign32.SIGN_INFO
                   {
                       cbSize = (uint)Marshal.SizeOf<MsSign32.SIGN_INFO>(),
                       callback = Marshal.GetFunctionPointerForDelegate(callbackDelegate),
                       pvOpaque = IntPtr.Zero
                   }))
            {
                var signerParams = new MsSign32.SIGNER_SIGN_EX3_PARAMS
                {
                    dwFlags = MsSign32.SIGN_CALLBACK_UNDOCUMENTED,
                    pSubjectInfo = signerSubjectInfo,
                    pSigningCert = signerCert,
                    pSignatureInfo = signerSignatureInfo,
                    pProviderInfo = IntPtr.Zero,
                    psRequest = IntPtr.Zero,
                    pCryptoPolicy = IntPtr.Zero,
                    pSignCallback = unmanagedSignInfo.Pointer
                };
                unmanagedSignerParams.Fill(signerParams);

                var hr = MsSign32.SignerSignEx3(
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
                    MsSign32.SignerFreeSignerContext(signerContext);
                }

                var tshr = MsSign32.S_OK;
                if (hr == MsSign32.S_OK && !string.IsNullOrWhiteSpace(timestampServer))
                {
                    Log.Trace($"Timestamping with url {timestampServer}");
                    var timestampRetries = 5;
                    do
                    {
                        tshr = timestampHashOid == MsSign32.OID_OIWSEC_SHA1
                            ? MsSign32.SignerTimeStamp(signerSubjectInfo, timestampServer)
                            : MsSign32.SignerTimeStampEx2(
                                MsSign32.SIGNER_TIMESTAMP_RFC3161,
                                signerSubjectInfo,
                                timestampServer,
                                timestampHashOid,
                                IntPtr.Zero,
                                IntPtr.Zero,
                                IntPtr.Zero
                            );
                        if (tshr == MsSign32.S_OK)
                        {
                            Log.Trace("Timestamping succeeded");
                        }
                        else
                        {
                            Log.Trace($"Timestamping failed with {tshr}, retries: {timestampRetries}");
                            Thread.Sleep(1000);
                        }
                    } while (tshr != MsSign32.S_OK && (timestampRetries--) > 0);
                }

                return (hr, tshr);
            }
        }

    

        public void UnsignFile(string fileName)
        {
            using (var file = new FileStream(fileName, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
            {
                // TODO: remove multiple certificates here?
                if (MsSign32.ImageEnumerateCertificates(file.SafeFileHandle, MsSign32.CERT_SECTION_TYPE_ANY,
                        out var dwNumCerts) &&
                    dwNumCerts == 1)
                {
                    MsSign32.ImageRemoveCertificate(file.SafeFileHandle, 0);
                }
            }
        }
    }
}