using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace SigningServer.Test
{
    public class CertificateHelper
    {

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptQueryObject(
            int dwObjectType,
            IntPtr pvObject,
            int dwExpectedContentTypeFlags,
            int dwExpectedFormatTypeFlags,
            int dwFlags,
            out int pdwMsgAndCertEncodingType,
            out int pdwContentType,
            out int pdwFormatType,
            ref IntPtr phCertStore,
            ref IntPtr phMsg,
            ref IntPtr ppvContext);

        public const int CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = (1 << 8);
        public const int CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED = (1 << 9);
        public const int CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = (1 << 10);
        public const int CERT_QUERY_FORMAT_FLAG_BINARY = (1 << 1);
        public const int CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED = (1 << 2);
        public const int CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED = (1 << 3);

        public const int CERT_QUERY_FORMAT_FLAG_ALL =
            CERT_QUERY_FORMAT_FLAG_BINARY |
            CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED |
            CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED;
        public const int CMSG_ENCODED_MESSAGE = 29;
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptMsgGetParam(
            IntPtr hCryptMsg,
            int dwParamType,
            int dwIndex,
            IntPtr pvData,
            ref int pcbData
        );

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptMsgGetParam(
            IntPtr hCryptMsg,
            int dwParamType,
            int dwIndex,
            [In, Out] byte[] vData,
            ref int pcbData
        );

        public static SignedCms GetDigitalCertificate(string filename)
        {
            X509Certificate2 cert = null;

            int encodingType;
            int contentType;
            int formatType;
            IntPtr certStore = IntPtr.Zero;
            IntPtr cryptMsg = IntPtr.Zero;
            IntPtr context = IntPtr.Zero;

            if (!CryptQueryObject(
                0x00000001,
                Marshal.StringToHGlobalUni(filename),
                (CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED
                 | CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED
                 | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED), // <-- These are the attributes that makes it fast!!
                CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                out encodingType,
                out contentType,
                out formatType,
                ref certStore,
                ref cryptMsg,
                ref context))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // Get size of the encoded message.
            int cbData = 0;
            if (!CryptMsgGetParam(
                cryptMsg,
                CMSG_ENCODED_MESSAGE,
                0,
                IntPtr.Zero,
                ref cbData))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var vData = new byte[cbData];

            // Get the encoded message.
            if (!CryptMsgGetParam(
                cryptMsg,
                CMSG_ENCODED_MESSAGE,
                0,
                vData,
                ref cbData))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var signedCms = new SignedCms();
            signedCms.Decode(vData);
            return signedCms;
        }
    }
}
