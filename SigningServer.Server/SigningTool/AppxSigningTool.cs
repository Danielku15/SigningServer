using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using NLog;

namespace SigningServer.Server.SigningTool
{
    public class AppxSigningTool : PortableExecutableSigningTool
    {
        private static readonly HashSet<string> PeSupportedExtensions =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".appx", ".appxbundle"
            };

        private static readonly Dictionary<string, uint> PeSupportedHashAlgorithms =
            new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase)
            {
                ["SHA256"] = MsSign32.CALG_SHA_256,
                ["SHA384"] = MsSign32.CALG_SHA_384,
                ["SHA512"] = MsSign32.CALG_SHA_512,
            };


        public override string[] SupportedFileExtensions => PeSupportedExtensions.ToArray();
        public override string[] SupportedHashAlgorithms => PeSupportedHashAlgorithms.Keys.ToArray();

        public override bool IsFileSupported(string fileName)
        {
            return PeSupportedExtensions.Contains(Path.GetExtension(fileName));
        }

        private protected override (int hr, int tshr) SignAndTimestamp(string inputFileName, string timestampServer,
            /*PSIGNER_SUBJECT_INFO*/ IntPtr signerSubjectInfo,
            /*PSIGNER_CERT*/ IntPtr signerCert,
            /*PSIGNER_SIGNATURE_INFO*/ IntPtr signerSignatureInfo,
            /*PSIGNER_PROVIDER_INFO*/ IntPtr signerProviderInfo)
        {
            timestampServer = timestampServer ?? "";

            using (var unmangedSipClientData = new UnmanagedStruct<MsSign32.APPX_SIP_CLIENT_DATA>())
            using (var unmanagedSignerParams = new UnmanagedStruct<MsSign32.SIGNER_SIGN_EX2_PARAMS>())
            {
                var signerParams = new MsSign32.SIGNER_SIGN_EX2_PARAMS
                {
                    pSubjectInfo = signerSubjectInfo,
                    pSigningCert = signerCert,
                    pSignatureInfo = signerSignatureInfo,
                    pProviderInfo = signerProviderInfo,
                    pszAlgorithmOid = null, // not needed for authenticode
                    pCryptAttrs = IntPtr.Zero, // no additional crypto attributes for signing
                    dwTimestampFlags = string.IsNullOrWhiteSpace(timestampServer)
                        ? 0
                        : MsSign32.SIGNER_TIMESTAMP_AUTHENTICODE,
                    pwszTimestampURL = string.IsNullOrWhiteSpace(timestampServer) ? null : timestampServer,
                    pSipData = unmangedSipClientData.Pointer
                };
                unmanagedSignerParams.Fill(signerParams);

                unmangedSipClientData.Fill(new MsSign32.APPX_SIP_CLIENT_DATA
                {
                    pSignerParams = unmanagedSignerParams.Pointer,
                    pAppxSipState = IntPtr.Zero
                });

                var hr = MsSign32.SignerSignEx2(
                    signerParams.dwFlags,
                    signerParams.pSubjectInfo,
                    signerParams.pSigningCert,
                    signerParams.pSignatureInfo,
                    signerParams.pProviderInfo,
                    signerParams.dwTimestampFlags,
                    signerParams.pszAlgorithmOid,
                    signerParams.pwszTimestampURL,
                    signerParams.pCryptAttrs,
                    signerParams.pSipData,
                    signerParams.pSignerContext,
                    signerParams.pCryptoPolicy,
                    signerParams.pReserved
                );

                if (signerParams.pSignerContext != IntPtr.Zero)
                {
                    var signerContext = new IntPtr();
                    Marshal.PtrToStructure(signerParams.pSignerContext, signerContext);
                    MsSign32.SignerFreeSignerContext(signerContext);
                }

                return (hr, MsSign32.S_OK);
            }
        }
    }
}