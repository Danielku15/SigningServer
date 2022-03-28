// using System;
// using System.Security.Cryptography;
// using System.Security.Cryptography.X509Certificates;
// using System.Xml;
//
// namespace SigningServer.Server.SigningTool
// {
//     public class SignedCmiManifest2
//     {
//         private readonly XmlDocument _manifestDom;
//
//         public SignedCmiManifest2(XmlDocument manifestDom)
//         {
//             _manifestDom = manifestDom;
//         }
//
//         public void Sign(AsymmetricAlgorithm privateKey, X509Certificate2 certificate, string timestampServer)
//         {
//             RemoveExistingSignature();
//             ReplacePublicKeyToken(privateKey);
//
//             XmlDocument licenseDom = null;
//             InsertPublisherIdentity(certificate);
//
//             licenseDom = CreateLicenseDom(signer, this.ExtractPrincipalFromManifest(),
//                 SignedCmiManifest2.ComputeHashFromManifest(this.m_manifestDom)
//             );
//             AuthenticodeSignLicenseDom(licenseDom, signer, timeStampUrl, this.m_useSha256);
//
//             StrongNameSignManifestDom(this.m_manifestDom, licenseDom, signer, this.m_useSha256);
//         }
//
//         private void ReplacePublicKeyToken(AsymmetricAlgorithm privateKey)
//         {
//             var namespaceManager = new XmlNamespaceManager(_manifestDom.NameTable);
//             namespaceManager.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v1");
//             if (!(GetSingleNode(_manifestDom, "asm:assembly/asm:assemblyIdentity",
//                     namespaceManager) is XmlElement singleNode))
//             {
//                 throw new CryptographicException(-2146762749);
//             }
//
//             if (!singleNode.HasAttribute("publicKeyToken"))
//             {
//                 throw new CryptographicException(-2146762749);
//             }
//
//             byte[] numArray;
//             if (privateKey is RSA rsa)
//             {
//                 // numArray = SignedCmiManifest2
//                 //     .GetFixedRSACryptoServiceProvider((RSACryptoServiceProvider)snKey, useSha256).ExportCspBlob(false);
//                 // if (numArray == null || numArray.Length == 0)
//                 //     throw new CryptographicException(-2146893821);
//                 fixed (byte* numPtr = numArray)
//                 {
//                     System.Deployment.Internal.CodeSigning.Win32.CRYPT_DATA_BLOB pCspPublicKeyBlob =
//                         new System.Deployment.Internal.CodeSigning.Win32.CRYPT_DATA_BLOB();
//                     pCspPublicKeyBlob.cbData = (uint)numArray.Length;
//                     pCspPublicKeyBlob.pbData = new IntPtr((void*)numPtr);
//                     IntPtr ppwszPublicKeyToken = new IntPtr();
//                     int publicKeyToken =
//                         System.Deployment.Internal.CodeSigning.Win32._AxlPublicKeyBlobToPublicKeyToken(
//                             ref pCspPublicKeyBlob, ref ppwszPublicKeyToken);
//                     if (publicKeyToken != 0)
//                         throw new CryptographicException(publicKeyToken);
//                     string stringUni = Marshal.PtrToStringUni(ppwszPublicKeyToken);
//                     System.Deployment.Internal.CodeSigning.Win32.HeapFree(
//                         System.Deployment.Internal.CodeSigning.Win32.GetProcessHeap(), 0U, ppwszPublicKeyToken);
//                     singleNode.SetAttribute("publicKeyToken", stringUni);
//                 }
//             }
//             else
//             {
//                 throw new CryptographicException(-2146762749);
//             }
//         }
//
//         private void RemoveExistingSignature()
//         {
//             var namespaceManager = new XmlNamespaceManager(_manifestDom.NameTable);
//             namespaceManager.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v1");
//             namespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
//             var singleNode = GetSingleNode(_manifestDom, "asm:assembly/ds:Signature", namespaceManager);
//             singleNode?.ParentNode.RemoveChild(singleNode);
//         }
//
//         private static XmlNode GetSingleNode(
//             XmlNode parentNode,
//             string xPath,
//             XmlNamespaceManager namespaceManager = null)
//         {
//             var xmlNodeList = namespaceManager != null
//                 ? parentNode.SelectNodes(xPath, namespaceManager)
//                 : parentNode.SelectNodes(xPath);
//             if (xmlNodeList == null)
//                 return null;
//             return xmlNodeList.Count <= 1 ? xmlNodeList[0] : throw new CryptographicException(-2146869247);
//         }
//     }
// }