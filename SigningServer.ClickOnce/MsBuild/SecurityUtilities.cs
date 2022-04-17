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
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SigningServer.MsSign;

namespace SigningServer.ClickOnce.MsBuild;

public class SecurityUtilities
{
    private const string Sha256SignatureMethodUri = @"http://www.w3.org/2000/09/xmldsig#rsa-sha256";
    private const string Sha256DigestMethod = @"http://www.w3.org/2000/09/xmldsig#sha256";
    
    static SecurityUtilities()
    {
        CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription),
            Sha256SignatureMethodUri);
#pragma warning disable SYSLIB0021 // Need to provide implementation
        CryptoConfig.AddAlgorithm(typeof(SHA256Managed),
            Sha256DigestMethod);
#pragma warning restore SYSLIB0021
    }
    
    public static void SignFile(X509Certificate2 cert, AsymmetricAlgorithm privateKey, string timestampUrl,
        string path)
    {
        if (cert == null)
        {
            throw new ArgumentNullException(nameof(cert));
        }

        if (string.IsNullOrEmpty(path))
        {
            throw new ArgumentNullException(nameof(path));
        }

        var useSha256 = UseSha256Algorithm(cert);

        var hModule = IntPtr.Zero;

        try
        {
            var doc = new XmlDocument { PreserveWhitespace = true };
            var xrSettings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore };
            using (var xr = XmlReader.Create(path, xrSettings))
            {
                doc.Load(xr);
            }

            var manifest = new SignedCmiManifest2(doc);
            var signer = new CmiManifestSigner2(privateKey, cert, useSha256);

            // Manifest signing uses .NET FX APIs, implemented in clr.dll.
            // Load the library explicitly.

            var clrDllDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "Microsoft.NET",
                Environment.Is64BitProcess ? "Framework64" : "Framework",
                "v4.0.30319");

            Win32.SetDllDirectoryW(clrDllDir);
            hModule = Win32.LoadLibraryExW(Path.Combine(clrDllDir, "clr.dll"), IntPtr.Zero,
                    Win32.LOAD_LIBRARY_AS_DATAFILE);
            // No need to check hModule - Sign() method will quickly fail if we did not load clr.dll

            manifest.Sign(signer, timestampUrl);
            doc.Save(path);
        }
        catch (Exception ex) when (Marshal.GetHRForException(ex) is -2147012889 or -2147012867)
        {
            throw new ApplicationException(ex.Message, ex);
        }
        catch (Exception ex)
        {
            throw new ApplicationException(ex.Message, ex);
        }
        finally
        {
            if (hModule != IntPtr.Zero)
            {
                Win32.FreeLibrary(hModule);
            }

            Win32.SetDllDirectoryW(null);
        }
    }

    private static bool UseSha256Algorithm(X509Certificate2 cert)
    {
        var oid = cert.SignatureAlgorithm;
        // Issue 6732: Clickonce does not support sha384/sha512 file hash so we default to sha256 
        // for certs with that signature algorithm.
        return string.Equals(oid.FriendlyName, "sha256RSA", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(oid.FriendlyName, "sha384RSA", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(oid.FriendlyName, "sha512RSA", StringComparison.OrdinalIgnoreCase);
    }
}
