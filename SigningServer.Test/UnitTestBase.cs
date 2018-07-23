using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using SigningServer.Contracts;

namespace SigningServer.Test
{
    public class UnitTestBase
    {
        [SetUp]
        public void SetupBase()
        {
            var deploymentItems = GetType().GetMethod(TestContext.CurrentContext.Test.Name).GetCustomAttributes<DeploymentItemAttribute>();
            foreach (var item in deploymentItems)
            {
                item.Deploy();
            }
        }

        protected void CanSign(ISigningTool signingTool, string fileName, string pfx, string hashAlgorithm = null)
        {
            var certificate = new X509Certificate2(pfx);
            Assert.IsTrue(signingTool.IsFileSupported(fileName));

            var response = new SignFileResponse();
            var request = new SignFileRequest
            {
                FileName = fileName,
                OverwriteSignature = false, 
                HashAlgorithm = hashAlgorithm
            };
            signingTool.SignFile(fileName, certificate, ConfigurationManager.AppSettings["TimestampServer"], request, response);

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

        protected byte[] CanResign(ISigningTool signingTool, string fileName, string pfx)
        {
            var certificate = new X509Certificate2(pfx);
            Assert.IsTrue(signingTool.IsFileSupported(fileName));

            var response = new SignFileResponse();
            var request = new SignFileRequest
            {
                FileName = fileName,
                OverwriteSignature = true
            };
            signingTool.SignFile(fileName, certificate, ConfigurationManager.AppSettings["TimestampServer"], request, response);

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
                return data.ToArray();
            }

        }

        protected void CannotResign(ISigningTool signingTool, string fileName, string pfx)
        {
            var certificate = new X509Certificate2(pfx);
            Assert.IsTrue(signingTool.IsFileSupported(fileName));

            var response = new SignFileResponse();
            var request = new SignFileRequest
            {
                FileName = fileName,
                OverwriteSignature = false
            };
            signingTool.SignFile(fileName, certificate, ConfigurationManager.AppSettings["TimestampServer"], request, response);

            Trace.WriteLine(response);
            Assert.AreEqual(SignFileResponseResult.FileAlreadySigned, response.Result);
            Assert.IsTrue(signingTool.IsFileSigned(fileName));
            Assert.IsInstanceOf<MemoryStream>(response.FileContent);
            Assert.AreEqual(response.FileSize, response.FileContent.Length);
            Assert.AreEqual(0, response.FileSize);
        }
    }
}
