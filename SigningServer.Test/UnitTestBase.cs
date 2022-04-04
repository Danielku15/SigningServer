using System;
using System.Diagnostics;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Contracts;

namespace SigningServer.Test
{
    public class UnitTestBase
    {
        internal static string ExecutionDirectory = AppDomain.CurrentDomain.BaseDirectory;
        protected static string TimestampServer = "http://timestamp.globalsign.com/tsa/r6advanced1";
        protected static string Sha1TimestampServer = "http://timestamp.sectigo.com";

        protected void CanSign(ISigningTool signingTool, string fileName, string hashAlgorithm = null)
        {
            Assert.IsTrue(signingTool.IsFileSupported(fileName));

            var response = new SignFileResponse();
            var request = new SignFileRequest
            {
                FileName = fileName,
                OverwriteSignature = false,
                HashAlgorithm = hashAlgorithm
            };
            var timestampServer = "SHA1".Equals(hashAlgorithm, StringComparison.OrdinalIgnoreCase)
                ? Sha1TimestampServer
                : TimestampServer;
            signingTool.SignFile(fileName, AssemblyEvents.Certificate, timestampServer, request, response);

            Assert.AreEqual(SignFileResponseResult.FileSigned, response.Result);
            Assert.IsTrue(signingTool.IsFileSigned(fileName));
            Assert.IsNotNull(response.FileContent);
            Assert.IsTrue(response.FileSize > 0);
            using (var data = new MemoryStream())
            {
                using (response.FileContent)
                {
                    response.FileContent.CopyTo(data);
                    Assert.AreEqual(response.FileSize, data.ToArray().Length);
                }
            }
        }


        public const string Sha1Oid = "1.3.14.3.2.26";
        public void EnsureSignature(string fileName, string hashAlgorithmOid)
        {
            var signerInfo = CertificateHelper.GetDigitalCertificate(fileName);
            Assert.IsNotNull(signerInfo);
            Assert.AreEqual(1, signerInfo.SignerInfos.Count);

            Assert.AreEqual(hashAlgorithmOid, signerInfo.SignerInfos[0].DigestAlgorithm.Value);
        }

        protected void CanResign(ISigningTool signingTool, string fileName)
        {
            Assert.IsTrue(signingTool.IsFileSupported(fileName));

            var response = new SignFileResponse();
            var request = new SignFileRequest
            {
                FileName = fileName,
                OverwriteSignature = true
            };
            signingTool.SignFile(fileName, AssemblyEvents.Certificate, TimestampServer, request, response);

            try
            {
                Assert.AreEqual(SignFileResponseResult.FileResigned, response.Result);
                Assert.IsTrue(signingTool.IsFileSigned(fileName));
                Assert.IsNotNull(response.FileContent);
                Assert.IsTrue(response.FileSize > 0);
                using (var data = new MemoryStream())
                {
                    using (response.FileContent)
                    {
                        response.FileContent.CopyTo(data);
                        Assert.AreEqual(response.FileSize, data.ToArray().Length);
                    }
                }
            }
            finally
            {
                response.Dispose();
            }
        }

        protected void CannotResign(ISigningTool signingTool, string fileName)
        {
            Assert.IsTrue(signingTool.IsFileSupported(fileName));

            var response = new SignFileResponse();
            var request = new SignFileRequest
            {
                FileName = fileName,
                OverwriteSignature = false
            };
            signingTool.SignFile(fileName, AssemblyEvents.Certificate, TimestampServer, request, response);

            Trace.WriteLine(response);
            try
            {
                Assert.AreEqual(SignFileResponseResult.FileAlreadySigned, response.Result);
                Assert.IsTrue(signingTool.IsFileSigned(fileName));
                Assert.AreEqual(0, response.FileSize);
            }
            finally
            {
                response.Dispose();
            }
        }
    }
}
