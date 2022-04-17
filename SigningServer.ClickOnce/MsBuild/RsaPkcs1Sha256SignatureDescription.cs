using System;
using System.Security.Cryptography;

namespace SigningServer.ClickOnce.MsBuild;

public class RsaPkcs1Sha256SignatureDescription : SignatureDescription
{
    public RsaPkcs1Sha256SignatureDescription()
    {
        KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
        DigestAlgorithm = typeof(SHA256).FullName;
        FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
        DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
    }

    public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
    {
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        var deformatter = new RSAPKCS1SignatureDeformatter(key);
        deformatter.SetHashAlgorithm("SHA256");
        return deformatter;
    }

    public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
    {
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        var formatter = new RSAPKCS1SignatureFormatter(key);
        formatter.SetHashAlgorithm("SHA256");
        return formatter;
    }

}
