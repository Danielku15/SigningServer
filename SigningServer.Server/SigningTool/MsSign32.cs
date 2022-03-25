using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

// ReSharper disable FieldCanBeMadeReadOnly.Global
// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global

namespace SigningServer.Server.SigningTool
{
    internal static class MsSign32
    {
        public const uint SIGNER_TIMESTAMP_AUTHENTICODE = 1;
        public const uint PKCS_7_ASN_ENCODING = 0x00010000;
        public const uint X509_ASN_ENCODING = 0x00000001;

        public const int S_OK = 0;

        public const uint PVK_TYPE_KEYCONTAINER = 0x2;

        public const uint SIGNER_NO_ATTR = 0;

        public const uint SIGNER_CERT_STORE = 2;

        public const uint SIGNER_CERT_POLICY_CHAIN = 2;

        public const uint SIGNER_SUBJECT_FILE = 1;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CERT_CONTEXT
        {
            public int dwCertEncodingType;
            public IntPtr pbCertEncoded;
            public int cbCertEncoded;
            public IntPtr pCertInfo;
            public IntPtr hCertStore;
        }

        [DllImport("crypt32.DLL", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr /*PCERT_CONTEXT*/ CertCreateCertificateContext(
            [In] uint dwCertEncodingType,
            [In] byte[] pbCertEncoded,
            [In] uint cbCertEncoded);

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CertFreeCertificateContext(
            [In] IntPtr /*PCERT_CONTEXT*/ pCertContext);


        public const string WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";

        public const uint ALG_CLASS_HASH = (4 << 13);
        public const uint ALG_TYPE_ANY = (0);

        public const uint ALG_SID_SHA1 = 4;
        public const uint ALG_SID_MD5 = 3;
        public const uint ALG_SID_SHA_256 = 12;
        public const uint ALG_SID_SHA_384 = 13;
        public const uint ALG_SID_SHA_512 = 14;

        public const uint CALG_SHA1 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1;
        public const uint CALG_MD5 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5;
        public const uint CALG_SHA_256 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256;
        public const uint CALG_SHA_384 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384;
        public const uint CALG_SHA_512 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512;

        public const int ERROR_SUCCESS = 0;

        [DllImport("mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int SignerSign(
            [In] /*PSIGNER_SUBJECT_INFO*/ IntPtr pSubjectInfo,
            [In] /*PSIGNER_CERT*/ IntPtr pSignerCert,
            [In] /*PSIGNER_SIGNATURE_INFO*/ IntPtr pSignatureInfo,
            [In, Optional] /*PSIGNER_PROVIDER_INFO*/ IntPtr pProviderInfo,
            [In, Optional] string pwszHttpTimeStamp,
            [In, Optional] /*PCRYPT_ATTRIBUTES*/ IntPtr psRequest,
            [In, Optional] IntPtr pSipData
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SIGNER_PROVIDER_INFO
        {
            public uint cbSize;
            public string pwszProviderName;
            public uint dwProviderType;
            public uint dwKeySpec;
            public uint dwPvkChoice;
            public SIGNER_PROVIDER_INFO_UNION union;
        }

        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
        public struct SIGNER_PROVIDER_INFO_UNION
        {
            [FieldOffset(0)] public string pwszPvkFileName;
            [FieldOffset(0)] public string pwszKeyContainer;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SIGNER_CERT
        {
            public uint cbSize;
            public uint dwCertChoice;
            public SIGNER_CERT_UNION union;
            public IntPtr hwnd;
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SIGNER_SIGNATURE_INFO
        {
            public uint cbSize;
            public uint algidHash;
            public uint dwAttrChoice;
            public SIGNER_SIGNATURE_INFO_UNION union;
            public /*PCRYPT_ATTRIBUTES*/ IntPtr psAuthenticated;
            public /*PCRYPT_ATTRIBUTES*/ IntPtr psUnauthenticated;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CRYPT_ATTRIBUTES
        {
            public uint cAttr;
            public /*PCRYPT_ATTRIBUTE*/ IntPtr rgAttr;
        }

        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
        public struct SIGNER_SIGNATURE_INFO_UNION
        {
            [FieldOffset(0)] public /*PSIGNER_ATTR_AUTHCODE*/ IntPtr pAttrAuthcode;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct SIGNER_CERT_STORE_INFO
        {
            public uint cbSize;
            public /*PCERT_CONTEXT*/ IntPtr pSigningCert;
            public uint dwCertPolicy;
            public IntPtr hCertStore;
        }

        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
        public struct SIGNER_CERT_UNION
        {
            [FieldOffset(0)] public /*PSIGNER_CERT_STORE_INFO*/ IntPtr pSpcChainInfo;
        }

        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
        public struct SIGNER_SUBJECT_INFO_UNION
        {
            [FieldOffset(0)] public /*PSIGNER_FILE_INFO*/ IntPtr pSignerFileInfo;
            // [FieldOffset(0)]
            // public SIGNER_BLOB_INFO* pSignerBlobInfo;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SIGNER_FILE_INFO
        {
            public uint cbSize;
            public string pwszFileName;
            public IntPtr hFile;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SIGNER_SUBJECT_INFO
        {
            public uint cbSize;
            public IntPtr pdwIndex;
            public uint dwSubjectChoice;
            public SIGNER_SUBJECT_INFO_UNION union;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SIGNER_CONTEXT
        {
            public uint cbSize;

            public uint cbBlob;

            public /*BYTE*/ IntPtr pbBlob;
        }

        [DllImport("mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int SignerSignEx(
            [In] uint dwFlags,
            [In] /*PSIGNER_SUBJECT_INFO*/ IntPtr pSubjectInfo,
            [In] /*PSIGNER_CERT*/ IntPtr pSignerCert,
            [In] /*PSIGNER_SIGNATURE_INFO*/ IntPtr pSignatureInfo,
            [In, Optional] /*PSIGNER_PROVIDER_INFO*/ IntPtr pProviderInfo,
            [In, Optional] string pwszHttpTimeStamp,
            [In, Optional] /*PCRYPT_ATTRIBUTES*/ IntPtr psRequest,
            [In, Optional] IntPtr pSipData,
            [Out] out SIGNER_CONTEXT ppSignerContext
        );

        [DllImport("mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int SignerSignEx2(
            [In] uint dwFlags,
            [In] /*PSIGNER_SUBJECT_INFO*/ IntPtr pSubjectInfo,
            [In] /*PSIGNER_CERT*/ IntPtr pSignerCert,
            [In] /*PSIGNER_SIGNATURE_INFO*/ IntPtr pSignatureInfo,
            [In, Optional] /*PSIGNER_PROVIDER_INFO*/ IntPtr pProviderInfo,
            [In, Optional] uint dwTimestampFlags,
            [In, Optional, MarshalAs(UnmanagedType.LPStr)]
            string pszAlgorithmOid,
            [In, Optional] string pwszTimestampURL,
            [In, Optional] /*PCRYPT_ATTRIBUTES*/ IntPtr psRequest,
            [In, Optional] IntPtr pSipData,
            [Out] /*PPSIGNER_CONTEXT*/IntPtr ppSignerContext,
            [In, Optional] IntPtr pCryptoPolicy,
            [Optional] IntPtr pReserved
        );

        [DllImport("mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int SignerFreeSignerContext(
            [In] /*PSIGNER_CONTEXT*/ IntPtr pSignerContext
        );

        [DllImport("mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int SignerTimeStamp(
            [In] /*PSIGNER_SUBJECT_INFO*/ IntPtr pSubjectInfo,
            [In] string pwszHttpTimeStamp,
            [In, Optional] /*PCRYPT_ATTRIBUTES*/ IntPtr psRequest,
            [In, Optional] IntPtr pSipData
        );


        public enum WinVerifyTrustResult : uint
        {
            Success = 0,
            ProviderUnknown = 0x800b0001, // Trust provider is not recognized on this system
            ActionUnknown = 0x800b0002, // Trust provider does not support the specified action
            SubjectFormUnknown = 0x800b0003, // Trust provider does not support the form specified for the subject
            SubjectNotTrusted = 0x800b0004, // Subject failed the specified verification action
            FileNotSigned = 0x800B0100, // TRUST_E_NOSIGNATURE - File was not signed
            SubjectExplicitlyDistrusted = 0x800B0111, // Signer's certificate is in the Untrusted Publishers store
            SignatureOrFileCorrupt = 0x80096010, // TRUST_E_BAD_DIGEST - file was probably corrupt
            SubjectCertExpired = 0x800B0101, // CERT_E_EXPIRED - Signer's certificate was expired
            SubjectCertificateRevoked = 0x800B010C, // CERT_E_REVOKED Subject's certificate was revoked

            UntrustedRoot =
                0x800B0109, // CERT_E_UNTRUSTEDROOT - A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider.

            LocalSecurityOption =
                0x80092026 // CRYPT_E_SECURITY_SETTINGS
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public WinTrustDataUIChoice dwUIChoice;
            public WinTrustDataRevocationChecks fdwRevocationChecks;
            public WinTrustDataUnionChoice dwUnionChoice;
            public WINTRUST_DATA_UNION union;
            public WinTrustDataStateAction dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public WinTrustDataProvFlags dwProvFlags;
            public uint dwUIContext;
        }


        [Flags]
        public enum WinTrustDataProvFlags : uint
        {
            UseIe4TrustFlag = 0x00000001,
            NoIe4ChainFlag = 0x00000002,
            NoPolicyUsageFlag = 0x00000004,
            RevocationCheckNone = 0x00000010,
            RevocationCheckEndCert = 0x00000020,
            RevocationCheckChain = 0x00000040,
            RevocationCheckChainExcludeRoot = 0x00000080,
            SaferFlag = 0x00000100, // Used by software restriction policies. Should not be used.
            HashOnlyFlag = 0x00000200,
            UseDefaultOsverCheck = 0x00000400,
            LifetimeSigningFlag = 0x00000800,
            CacheOnlyUrlRetrieval = 0x00001000, // affects CRL retrieval and AIA retrieval
            DisableMD2andMD4 = 0x00002000 // Win7 SP1+: Disallows use of MD2 or MD4 in the chain except for the root
        }


        public enum WinTrustDataStateAction : uint
        {
            Ignore = 0x00000000,
            Verify = 0x00000001,
            Close = 0x00000002,
            AutoCache = 0x00000003,
            AutoCacheFlush = 0x000000041
        }


        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
        public struct WINTRUST_DATA_UNION
        {
            [FieldOffset(0)] public /*PWINTRUST_FILE_INFO*/ IntPtr pFile; // individual file
            // public WINTRUST_CATALOG_INFO* pCatalog; // member of a Catalog File
            // public WINTRUST_BLOB_INFO* pBlob; // memory blob
            // public WINTRUST_SGNR_INFO* pSgnr; // signer structure only
            // public WINTRUST_CERT_INFO* pCert;
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }


        public enum WinTrustDataUIChoice : uint
        {
            All = 1,
            None = 2,
            NoBad = 3,
            NoGood = 4
        }

        public enum WinTrustDataRevocationChecks : uint
        {
            None = 0x00000000,
            WholeChain = 0x00000001
        }

        public enum WinTrustDataUnionChoice : uint
        {
            File = 1,
            Catalog = 2,
            Blob = 3,
            Signer = 4,
            Certificate = 5
        }


        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        public static extern WinVerifyTrustResult WinVerifyTrust(
            [In] IntPtr hwnd,
            [In] [MarshalAs(UnmanagedType.LPStruct)]
            Guid pgActionID,
            [In] WINTRUST_DATA pWVTData
        );

        [DllImport("imagehlp.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ImageEnumerateCertificates(
            [In] SafeFileHandle FileHandle,
            [In] uint TypeFilter,
            [Out] out uint CertificateCount,
            [In, Out, Optional] uint[] Indices,
            [In, Optional] uint IndexCount
        );


        public const uint CERT_SECTION_TYPE_ANY = 0xFF;

        [DllImport("imagehlp.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ImageRemoveCertificate(SafeFileHandle fileHandle, uint index);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SIGNER_SIGN_EX2_PARAMS
        {
            public uint dwFlags;
            public /*PSIGNER_SUBJECT_INFO*/ IntPtr pSubjectInfo;
            public /*PSIGNER_CERT*/ IntPtr pSigningCert;
            public /*PSIGNER_SIGNATURE_INFO*/ IntPtr pSignatureInfo;
            public /*PSIGNER_PROVIDER_INFO*/ IntPtr pProviderInfo;
            public uint dwTimestampFlags;
            public string pszAlgorithmOid;
            [MarshalAs(UnmanagedType.LPWStr)] public string pwszTimestampURL;
            public /*PCRYPT_ATTRIBUTES*/ IntPtr pCryptAttrs;
            public IntPtr pSipData;
            public /*PPSIGNER_CONTEXT*/ IntPtr pSignerContext;
            public IntPtr pCryptoPolicy;
            public IntPtr pReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct APPX_SIP_CLIENT_DATA
        {
            public /*PSIGNER_SIGN_EX2_PARAMS*/ IntPtr pSignerParams;
            public /*LPVOID*/ IntPtr pAppxSipState;
        }

        public const uint CERT_KEY_PROV_INFO_PROP_ID = 2;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CRYPT_KEY_PROV_INFO
        {
            public string pwszContainerName;
            public string pwszProvName;
            public uint dwProvType;
            public uint dwFlags;
            public uint cProvParam;
            public IntPtr rgProvParam;
            public uint dwKeySpec;
        }

        public const int CRYPT_E_NOT_FOUND = unchecked((int)0x80092004); // Cannot find object or property.

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CertGetCertificateContextProperty(
            [In] IntPtr pCertContext,
            [In] uint dwPropId,
            [In, Out] IntPtr pvData,
            [In, Out] ref uint pcbData);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalAlloc(LocalMemoryFlags uFlags, UIntPtr uBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr handle);

        [Flags]
        public enum LocalMemoryFlags : uint
        {
            LMEM_FIXED = 0x0000,
            LMEM_MOVEABLE = 0x0002,
            LMEM_NOCOMPACT = 0x0010,
            LMEM_NODISCARD = 0x0020,
            LMEM_ZEROINIT = 0x0040,
            LMEM_MODIFY = 0x0080,
            LMEM_DISCARDABLE = 0x0F00,
            LMEM_VALID_FLAGS = 0x0F72,
            LMEM_INVALID_HANDLE = 0x8000,
            LHND = (LMEM_MOVEABLE | LMEM_ZEROINIT),
            LPTR = (LMEM_FIXED | LMEM_ZEROINIT),
            NONZEROLHND = (LMEM_MOVEABLE),
            NONZEROLPTR = (LMEM_FIXED)
        }
    }
}