/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2022 Daniel Kuschny (Adaptation for SigningServer)
 * Copyright (c) .NET Foundation and contributors
 * 
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using SigningServer.MsSign;

namespace SigningServer.ClickOnce.MsBuild;

public class SignedCmiManifest2
{
    private const string AssemblyNamespaceUri = "urn:schemas-microsoft-com:asm.v1";
    private const string AssemblyV2NamespaceUri = "urn:schemas-microsoft-com:asm.v2";
    private const string LicenseNamespaceUri = "urn:mpeg:mpeg21:2003:01-REL-R-NS";
    private const string AuthenticodeNamespaceUri = "http://schemas.microsoft.com/windows/pki/2005/Authenticode";
    private const string Sha1SignatureMethodUri = @"http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    private const string Sha256SignatureMethodUri = @"http://www.w3.org/2000/09/xmldsig#rsa-sha256";
    private const string Sha1DigestMethod = @"http://www.w3.org/2000/09/xmldsig#sha1";
    private const string Sha256DigestMethod = @"http://www.w3.org/2000/09/xmldsig#sha256";
    private const string MSRelNamespaceUri = "http://schemas.microsoft.com/windows/rel/2005/reldata";

    private const string LicenseTemplate = "<r:license xmlns:r=\"" + LicenseNamespaceUri + "\" xmlns:as=\"" +
                                           AuthenticodeNamespaceUri + "\">" +
                                           @"<r:grant>" +
                                           @"<as:ManifestInformation>" +
                                           @"<as:assemblyIdentity />" +
                                           @"</as:ManifestInformation>" +
                                           @"<as:SignedBy/>" +
                                           @"<as:AuthenticodePublisher>" +
                                           @"<as:X509SubjectName>CN=dummy</as:X509SubjectName>" +
                                           @"</as:AuthenticodePublisher>" +
                                           @"</r:grant><r:issuer></r:issuer></r:license>";

    private readonly XmlDocument _manifestDom;

    public SignedCmiManifest2(XmlDocument manifestDom)
    {
        _manifestDom = manifestDom;
    }

    public void Sign(CmiManifestSigner2 signer, string timeStampUrl)
    {
        // Remove existing SN signature.
        RemoveExistingSignature(_manifestDom);

        // Replace public key token in assemblyIdentity if requested.
        ReplacePublicKeyToken(_manifestDom, signer.StrongNameKey);

        // No cert means don't Authenticode sign and timestamp.
        XmlDocument? licenseDom = null;
        if (signer.Certificate != null)
        {
            // Yes. We will Authenticode sign, so first insert <publisherIdentity />
            // element, if necessary.
            InsertPublisherIdentity(_manifestDom, signer.Certificate);

            // Now create the license DOM, and then sign it.
            licenseDom = CreateLicenseDom(signer, ExtractPrincipalFromManifest(),
                ComputeHashFromManifest(_manifestDom, signer.UseSha256));
            AuthenticodeSignLicenseDom(licenseDom, signer, timeStampUrl);
        }

        StrongNameSignManifestDom(_manifestDom, licenseDom, signer);
    }

    private static void AuthenticodeSignLicenseDom(XmlDocument licenseDom, CmiManifestSigner2 signer,
        string timeStampUrl)
    {
        // Make sure it is RSA, as this is the only one Fusion will support.
        if (signer.StrongNameKey is not RSA rsaPrivateKey)
        {
            throw new NotSupportedException();
        }

        // Setup up XMLDSIG engine.
        var signedXml = new ManifestSignedXml2(licenseDom);
        // only needs to change the provider type when RSACryptoServiceProvider is used
        signedXml.SigningKey = rsaPrivateKey;
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = signer.UseSha256 ? Sha256SignatureMethodUri : Sha1SignatureMethodUri;

        // Add the key information.
        signedXml.KeyInfo.AddClause(new RSAKeyValue(rsaPrivateKey));
        signedXml.KeyInfo.AddClause(new KeyInfoX509Data(signer.Certificate!, X509IncludeOption.ExcludeRoot));

        // Add the enveloped reference.
        var reference = new Reference
        {
            Uri = "", DigestMethod = signer.UseSha256 ? Sha256DigestMethod : Sha1DigestMethod
        };

        // Add an enveloped and an Exc-C14N transform.
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());

        // Add the reference.
        signedXml.AddReference(reference);

        // Compute the signature.
        signedXml.ComputeSignature();

        // Get the XML representation
        var xmlDigitalSignature = signedXml.GetXml();
        xmlDigitalSignature.SetAttribute("Id", "AuthenticodeSignature");

        // Insert the signature node under the issuer element.
        var nsm = new XmlNamespaceManager(licenseDom.NameTable);
        nsm.AddNamespace("r", LicenseNamespaceUri);
        var issuerNode = (XmlElement)licenseDom.SelectSingleNode("r:license/r:issuer", nsm)!;
        issuerNode.AppendChild(licenseDom.ImportNode(xmlDigitalSignature, true));

        // Time stamp it if requested.
        if (!string.IsNullOrEmpty(timeStampUrl))
        {
            TimestampSignedLicenseDom(licenseDom, timeStampUrl, signer.UseSha256);
        }

        // Wrap it inside a RelData element.
        licenseDom.DocumentElement!.ParentNode!.InnerXml = "<msrel:RelData xmlns:msrel=\"" +
                                                           MSRelNamespaceUri + "\">" +
                                                           licenseDom.OuterXml + "</msrel:RelData>";
    }


    private static void TimestampSignedLicenseDom(XmlDocument licenseDom, string timeStampUrl, bool useSha256)
    {
        var nsm = new XmlNamespaceManager(licenseDom.NameTable);
        nsm.AddNamespace("r", LicenseNamespaceUri);
        nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        nsm.AddNamespace("as", AuthenticodeNamespaceUri);

        string timestamp;
        try
        {
            // Try RFC3161 first
            var signatureValueNode =
                (XmlElement)licenseDom.SelectSingleNode("r:license/r:issuer/ds:Signature/ds:SignatureValue", nsm)!;
            var signatureValue = signatureValueNode.InnerText;
            timestamp = ObtainRFC3161Timestamp(timeStampUrl, signatureValue, useSha256);
        }
        // Catch CryptographicException to ensure fallback to old code (non-RFC3161)
        catch (CryptographicException)
        {
            var timestampBlob = new Win32.CRYPT_DATA_BLOB();

            var licenseXml = Encoding.UTF8.GetBytes(licenseDom.OuterXml);

            unsafe
            {
                fixed (byte* pbLicense = licenseXml)
                {
                    var licenseBlob = new Win32.CRYPT_DATA_BLOB();
                    var pvLicense = new IntPtr(pbLicense);
                    licenseBlob.cbData = (uint)licenseXml.Length;
                    licenseBlob.pbData = pvLicense;

                    var hr = Win32.CertTimestampAuthenticodeLicense(ref licenseBlob, timeStampUrl,
                        ref timestampBlob);
                    if (hr != Win32.S_OK)
                    {
                        throw new CryptographicException(hr);
                    }
                }
            }

            var timestampSignature = new byte[timestampBlob.cbData];
            Marshal.Copy(timestampBlob.pbData, timestampSignature, 0, timestampSignature.Length);
            Win32.HeapFree(Win32.GetProcessHeap(), 0, timestampBlob.pbData);
            timestamp = Encoding.UTF8.GetString(timestampSignature);
        }

        var asTimestamp = licenseDom.CreateElement("as", "Timestamp", AuthenticodeNamespaceUri);
        asTimestamp.InnerText = timestamp;

        var dsObject = licenseDom.CreateElement("Object", SignedXml.XmlDsigNamespaceUrl);
        dsObject.AppendChild(asTimestamp);

        var signatureNode = (XmlElement)licenseDom.SelectSingleNode("r:license/r:issuer/ds:Signature", nsm)!;
        signatureNode.AppendChild(dsObject);
    }

    private static string ObtainRFC3161Timestamp(string timeStampUrl, string signatureValue, bool useSha256)
    {
        var sigValueBytes = Convert.FromBase64String(signatureValue);
        string timestamp;

        var algId = useSha256 ? Win32.szOID_NIST_sha256 : Win32.szOID_OIWSEC_sha1;

        unsafe
        {
            var ppTsContext = IntPtr.Zero;
            var ppTsSigner = IntPtr.Zero;
            var phStore = IntPtr.Zero;

            try
            {
                var nonce = new byte[24];

                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(nonce);
                }

                var para = new Win32.CRYPT_TIMESTAMP_PARA { fRequestCerts = true, pszTSAPolicyId = IntPtr.Zero };

                fixed (byte* pbNonce = nonce)
                {
                    para.Nonce.cbData = (uint)nonce.Length;
                    para.Nonce.pbData = (IntPtr)pbNonce;

                    if (!Win32.CryptRetrieveTimeStamp(
                            timeStampUrl,
                            0,
                            60 * 1000, // 1 minute timeout
                            algId,
                            ref para,
                            sigValueBytes,
                            sigValueBytes.Length,
                            ref ppTsContext,
                            ref ppTsSigner,
                            ref phStore))
                    {
                        throw new CryptographicException(Marshal.GetLastWin32Error());
                    }
                }

                var timestampContext =
                    (Win32.CRYPT_TIMESTAMP_CONTEXT)Marshal.PtrToStructure(ppTsContext,
                        typeof(Win32.CRYPT_TIMESTAMP_CONTEXT))!;
                var encodedBytes = new byte[(int)timestampContext.cbEncoded];
                Marshal.Copy(timestampContext.pbEncoded, encodedBytes, 0, (int)timestampContext.cbEncoded);
                timestamp = Convert.ToBase64String(encodedBytes);
            }
            finally
            {
                if (ppTsContext != IntPtr.Zero)
                {
                    Win32.CryptMemFree(ppTsContext);
                }

                if (ppTsSigner != IntPtr.Zero)
                {
                    Win32.CertFreeCertificateContext(ppTsSigner);
                }

                if (phStore != IntPtr.Zero)
                {
                    Win32.CertCloseStore(phStore, 0);
                }
            }
        }

        return timestamp;
    }

    private static void StrongNameSignManifestDom(XmlDocument manifestDom, XmlDocument? licenseDom,
        CmiManifestSigner2 signer)
    {
        // Make sure it is RSA, as this is the only one Fusion will support.
        if (signer.StrongNameKey is not RSA snKey)
        {
            throw new NotSupportedException();
        }

        // Setup namespace manager.
        var nsm = new XmlNamespaceManager(manifestDom.NameTable);
        nsm.AddNamespace("asm", AssemblyNamespaceUri);

        // Get to root element.
        if (manifestDom.SelectSingleNode("asm:assembly", nsm) is not XmlElement signatureParent)
        {
            throw new CryptographicException(Win32.TRUST_E_SUBJECT_FORM_UNKNOWN);
        }

        if (signer.StrongNameKey is not RSA)
        {
            throw new NotSupportedException();
        }

        // Setup up XMLDSIG engine.
        var signedXml = new ManifestSignedXml2(signatureParent);
        signedXml.SigningKey = signer.StrongNameKey;

        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        if (signer.UseSha256)
        {
            signedXml.SignedInfo.SignatureMethod = Sha256SignatureMethodUri;
        }
        else
        {
            signedXml.SignedInfo.SignatureMethod = Sha1SignatureMethodUri;
        }

        // Add the key information.
        signedXml.KeyInfo.AddClause(new RSAKeyValue(snKey));
        if (licenseDom != null)
        {
            signedXml.KeyInfo.AddClause(new KeyInfoNode(licenseDom.DocumentElement!));
        }

        signedXml.KeyInfo.Id = "StrongNameKeyInfo";

        // Add the enveloped reference.
        var enveloped = new Reference();
        enveloped.Uri = "";
        if (signer.UseSha256)
        {
            enveloped.DigestMethod = Sha256DigestMethod;
        }
        else
        {
            enveloped.DigestMethod = Sha1DigestMethod;
        }

        // Add an enveloped then Exc-C14N transform.
        enveloped.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        enveloped.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(enveloped);

#if (false) // DSIE: New format does not sign KeyInfo.
            // Add the key info reference.
            Reference strongNameKeyInfo = new Reference();
            strongNameKeyInfo.Uri = "#StrongNameKeyInfo";
            strongNameKeyInfo.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(strongNameKeyInfo);
#endif
        // Compute the signature.
        signedXml.ComputeSignature();

        // Get the XML representation
        var xmlDigitalSignature = signedXml.GetXml();
        xmlDigitalSignature.SetAttribute("Id", "StrongNameSignature");

        // Insert the signature now.
        signatureParent.AppendChild(xmlDigitalSignature);
    }

    private static byte[] ComputeHashFromManifest(XmlDocument manifestDom, bool useSha256)
    {
        // Since the DOM given to us is not guaranteed to be normalized,
        // we need to normalize it ourselves. Also, we always preserve
        // white space as Fusion XML engine always preserve white space.
        var normalizedDom = new XmlDocument { PreserveWhitespace = true };

        // Normalize the document
        using (var stringReader = new StringReader(manifestDom.OuterXml))
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
            var reader = XmlReader.Create(stringReader, settings, manifestDom.BaseURI);
            normalizedDom.Load(reader);
        }

        var exc = new XmlDsigExcC14NTransform();
        exc.LoadInput(normalizedDom);

        if (useSha256)
        {
            using var sha2 = SHA256.Create();
            var hash = sha2.ComputeHash((MemoryStream)exc.GetOutput());
            if (hash == null)
            {
                throw new CryptographicException(Win32.TRUST_E_BAD_DIGEST);
            }

            return hash;
        }
        else
        {
            using var sha1 = SHA1.Create();
            var hash = sha1.ComputeHash((MemoryStream)exc.GetOutput());
            if (hash == null)
            {
                throw new CryptographicException(Win32.TRUST_E_BAD_DIGEST);
            }

            return hash;
        }
    }


    private static XmlDocument CreateLicenseDom(CmiManifestSigner2 signer, XmlElement? principal, byte[] hash)
    {
        var licenseDom = new XmlDocument { PreserveWhitespace = true };
        licenseDom.LoadXml(LicenseTemplate);
        var nsm = new XmlNamespaceManager(licenseDom.NameTable);
        nsm.AddNamespace("r", LicenseNamespaceUri);
        nsm.AddNamespace("as", AuthenticodeNamespaceUri);
        var assemblyIdentityNode =
            (XmlElement)licenseDom.SelectSingleNode("r:license/r:grant/as:ManifestInformation/as:assemblyIdentity", nsm)
            !;
        assemblyIdentityNode.RemoveAllAttributes();
        if (principal != null)
        {
            foreach (XmlAttribute attribute in principal.Attributes)
            {
                assemblyIdentityNode.SetAttribute(attribute.Name, attribute.Value);
            }    
        }

        var manifestInformationNode =
            (XmlElement)licenseDom.SelectSingleNode("r:license/r:grant/as:ManifestInformation", nsm)!;

        manifestInformationNode.SetAttribute("Hash", hash.Length == 0 ? "" : BytesToHexString(hash, 0, hash.Length));
        manifestInformationNode.SetAttribute("Description", "");
        manifestInformationNode.SetAttribute("Url", "");

        var authenticodePublisherNode =
            (XmlElement)licenseDom.SelectSingleNode("r:license/r:grant/as:AuthenticodePublisher/as:X509SubjectName",
                nsm)!;
        authenticodePublisherNode.InnerText = signer.Certificate!.SubjectName.Name;

        return licenseDom;
    }

    private static readonly char[] HexValues =
    {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private static string? BytesToHexString(IReadOnlyList<byte>? array, int start, int end)
    {
        if (array == null)
        {
            return null;
        }

        var hexOrder = new char[(end - start) * 2];
        var i = end;
        var j = 0;
        while (i-- > start)
        {
            var digit = (array[i] & 0xf0) >> 4;
            hexOrder[j++] = HexValues[digit];
            digit = (array[i] & 0x0f);
            hexOrder[j++] = HexValues[digit];
        }

        return new string(hexOrder);
    }

    private XmlElement? ExtractPrincipalFromManifest()
    {
        var nsm = new XmlNamespaceManager(_manifestDom.NameTable);
        nsm.AddNamespace("asm", AssemblyNamespaceUri);
        var assemblyIdentityNode = _manifestDom.SelectSingleNode("asm:assembly/asm:assemblyIdentity", nsm);
        if (assemblyIdentityNode == null)
            throw new CryptographicException(Win32.TRUST_E_SUBJECT_FORM_UNKNOWN);
        return assemblyIdentityNode as XmlElement;
    }

    private static void InsertPublisherIdentity(XmlDocument manifestDom, X509Certificate2 signerCert)
    {
        var nsm = new XmlNamespaceManager(manifestDom.NameTable);
        nsm.AddNamespace("asm", AssemblyNamespaceUri);
        nsm.AddNamespace("asm2", AssemblyV2NamespaceUri);
        nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

        var assembly = (XmlElement)manifestDom.SelectSingleNode("asm:assembly", nsm)!;
        if (manifestDom.SelectSingleNode("asm:assembly/asm:assemblyIdentity", nsm) is not XmlElement)
        {
            throw new CryptographicException(Win32.TRUST_E_SUBJECT_FORM_UNKNOWN);
        }

        // Reuse existing node if exists
        if (manifestDom.SelectSingleNode("asm:assembly/asm2:publisherIdentity",
                nsm) is not XmlElement publisherIdentity)
        {
            // create new if not exist
            publisherIdentity = manifestDom.CreateElement("publisherIdentity", AssemblyV2NamespaceUri);
        }

        // Get the issuer's public key blob hash.
        var pIssuerKeyHash = new IntPtr();
        var hr = Win32._AxlGetIssuerPublicKeyHash(signerCert.Handle, ref pIssuerKeyHash);
        if (hr != Win32.S_OK)
        {
            throw new CryptographicException(hr);
        }

        var issuerKeyHash = Marshal.PtrToStringUni(pIssuerKeyHash);
        Win32.HeapFree(Win32.GetProcessHeap(), 0, pIssuerKeyHash);

        publisherIdentity.SetAttribute("name", signerCert.SubjectName.Name);
        publisherIdentity.SetAttribute("issuerKeyHash", issuerKeyHash);

        if (manifestDom.SelectSingleNode("asm:assembly/ds:Signature", nsm) is XmlElement signature)
        {
            assembly.InsertBefore(publisherIdentity, signature);
        }
        else
        {
            assembly.AppendChild(publisherIdentity);
        }
    }


    private static void ReplacePublicKeyToken(XmlDocument manifestDom, AsymmetricAlgorithm snKey)
    {
        // Make sure we can find the publicKeyToken attribute.
        var nsm = new XmlNamespaceManager(manifestDom.NameTable);
        nsm.AddNamespace("asm", AssemblyNamespaceUri);
        if (manifestDom.SelectSingleNode("asm:assembly/asm:assemblyIdentity", nsm) is not XmlElement assemblyIdentity)
        {
            throw new CryptographicException(Win32.TRUST_E_SUBJECT_FORM_UNKNOWN);
        }

        if (!assemblyIdentity.HasAttribute("publicKeyToken"))
        {
            throw new CryptographicException(Win32.TRUST_E_SUBJECT_FORM_UNKNOWN);
        }

        byte[] cspPublicKeyBlob;

        if (snKey is RSACryptoServiceProvider rsacsp)
        {
            cspPublicKeyBlob = rsacsp.ExportCspBlob(false);
            if (cspPublicKeyBlob == null || cspPublicKeyBlob.Length == 0)
            {
                throw new CryptographicException(Win32.NTE_BAD_KEY);
            }
        }
        else
        {
            using var rsaCsp = new RSACryptoServiceProvider();
            rsaCsp.ImportParameters(((RSA)snKey).ExportParameters(false));
            cspPublicKeyBlob = rsaCsp.ExportCspBlob(false);
        }

        // Now compute the public key token.
        unsafe
        {
            fixed (byte* pbPublicKeyBlob = cspPublicKeyBlob)
            {
                var publicKeyBlob = new Win32.CRYPT_DATA_BLOB
                {
                    cbData = (uint)cspPublicKeyBlob.Length, pbData = new IntPtr(pbPublicKeyBlob)
                };
                var pPublicKeyToken = new IntPtr();

                var hr = Win32._AxlPublicKeyBlobToPublicKeyToken(ref publicKeyBlob, ref pPublicKeyToken);
                if (hr != Win32.S_OK)
                {
                    throw new CryptographicException(hr);
                }

                var publicKeyToken = Marshal.PtrToStringUni(pPublicKeyToken);
                Win32.HeapFree(Win32.GetProcessHeap(), 0, pPublicKeyToken);

                assemblyIdentity.SetAttribute("publicKeyToken", publicKeyToken);
            }
        }
    }

    private static void RemoveExistingSignature(XmlDocument manifestDom)
    {
        var nsm = new XmlNamespaceManager(manifestDom.NameTable);
        nsm.AddNamespace("asm", AssemblyNamespaceUri);
        nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        var signatureNode = manifestDom.SelectSingleNode("asm:assembly/ds:Signature", nsm);
        if (signatureNode != null)
        {
            signatureNode.ParentNode!.RemoveChild(signatureNode);
        }
    }
}
