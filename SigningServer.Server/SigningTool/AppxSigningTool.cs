using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NLog;

namespace SigningServer.Server.SigningTool
{
    public class AppxSigningTool : PortableExecutableSigningTool
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();
        private static readonly HashSet<string> AppxSupportedExtensions =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".appx", ".appxbundle", ".eappx", ".eappxbundle",
                ".msix", ".emsix", ".msixbundle", ".emsixbundle"
            };

        public override string[] SupportedFileExtensions => AppxSupportedExtensions.ToArray();
        public override bool IsFileSupported(string fileName)
        {
            return AppxSupportedExtensions.Contains(Path.GetExtension(fileName));
        }

        private protected override (int hr, int tshr) SignAndTimestamp(
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
            using (var unmanagedSipData = new UnmanagedStruct<MsSign32.APPX_SIP_CLIENT_DATA>(new MsSign32.APPX_SIP_CLIENT_DATA
                   {
                       pSignerParams = unmanagedSignerParams.Pointer,
                       pAppxSipState = IntPtr.Zero
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
                    pSignCallback = unmanagedSignInfo.Pointer,
                    pwszTimestampURL = timestampServer,
                    dwTimestampFlags = MsSign32.SIGNER_TIMESTAMP_RFC3161,
                    pszTimestampAlgorithmOid = timestampHashOid
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
                    unmanagedSipData.Pointer,
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

                var appxSip = Marshal.PtrToStructure<MsSign32.APPX_SIP_CLIENT_DATA>(unmanagedSipData.Pointer);
                if (appxSip.pAppxSipState != IntPtr.Zero)
                {
                    Marshal.Release(appxSip.pAppxSipState);
                }
                
                return (hr, MsSign32.S_OK);
            }
        }
    }
}