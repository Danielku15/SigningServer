﻿using System.Collections.Generic;
using SigningServer.Android.IO;

namespace SigningServer.Android.Security.Cert
{
    public class CertificateFactory
    {
        public static CertificateFactory GetInstance(string s)
        {
            throw new System.NotImplementedException();
        }

        public X509Certificate GenerateCertificate(InputStream byteArrayInputStream)
        {
            throw new System.NotImplementedException();
        }

        public IEnumerable<Certificate> GenerateCertificates(InputStream byteArrayInputStream)
        {
            throw new System.NotImplementedException();
        }
    }
}