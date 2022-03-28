using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using RSAKeyVaultProvider;

namespace SigningServer.Server.SigningTool
{
    /// <summary>
    /// This is a <see cref="X509Certificate2"/>
    /// </summary>
    public class AzureX509Certificate2 : X509Certificate2
    {
        public AzureX509Certificate2(byte[] rawData)
            : base(rawData)
        {
        }

        public void SetAzurePrivateKey(TokenCredential credentials, Uri keyId)
        {
            var privateKey = RSAFactory.Create(credentials, keyId, this);


#if NET48
            // NOTE: Here we need to trick a bit, we cannot set a different PrivateKey value for the certificate so easy

            // Set Fake Private key just to satisfy HasPrivateKey
            // we do this low level to not undergo any key checks which are done in the PrivateKey setter
            var certContext = typeof(X509Certificate2)
                .GetField("m_safeCertContext", BindingFlags.Instance | BindingFlags.NonPublic)
                ?.GetValue(this);
            typeof(X509Certificate2).GetMethod("SetPrivateKeyProperty", BindingFlags.Static | BindingFlags.NonPublic)
                ?.Invoke(null, new[]
                {
                    certContext,
                    new RSACryptoServiceProvider()
                });

            // Set Private Key internally so it is loaded on the getter
            var privateKeyField =
                typeof(X509Certificate2).GetField("m_privateKey", BindingFlags.Instance | BindingFlags.NonPublic);
            var oldPrivateKey = privateKeyField?.GetValue(this);
            (oldPrivateKey as IDisposable)?.Dispose();
            privateKeyField?.SetValue(this, privateKey);
#else
            #error Implement me for the right platform
#endif
        }
    }
}