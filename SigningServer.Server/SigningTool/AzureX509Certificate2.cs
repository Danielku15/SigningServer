using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SigningServer.Server.SigningTool
{
    public class AzureX509Certificate2 : X509Certificate2
    {
        public AzureX509Certificate2(byte[] rawData)
            : base(rawData)
        {
        }

        public void ReplacePrivateKey(AsymmetricAlgorithm privateKey)
        {
            // Set Fake Private key just to satisfy HasPrivateKey
            // X509Certificate2.SetPrivateKeyProperty(this.m_safeCertContext, asymmetricAlgorithm);
            var certContext = typeof(X509Certificate2)
                .GetField("m_safeCertContext", BindingFlags.Instance | BindingFlags.NonPublic)
                .GetValue(this);
            typeof(X509Certificate2).GetMethod("SetPrivateKeyProperty", BindingFlags.Static | BindingFlags.NonPublic)
                .Invoke(null, new[]
                {
                    certContext,
                    new RSACryptoServiceProvider()
                });
            
            // Set Private Key for getter
            var privateKeyField =
                typeof(X509Certificate2).GetField("m_privateKey", BindingFlags.Instance | BindingFlags.NonPublic);
            var oldPrivateKey = privateKeyField.GetValue(this);
            (oldPrivateKey as IDisposable)?.Dispose();
            privateKeyField?.SetValue(this, privateKey);
        }
    }
}