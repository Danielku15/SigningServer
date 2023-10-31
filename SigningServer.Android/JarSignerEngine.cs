using SigningServer.Android.Collections;
using SigningServer.Android.Com.Android.Apksig;
using SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1;

namespace SigningServer.Android
{
    public class JarSignerEngine : DefaultApkSignerEngine
    {
        public JarSignerEngine(List<ApkSigner.SignerConfig> signerConfigs, DigestAlgorithm digestAlgorithm)
            : base(MapSignerConfigs(signerConfigs),
                null,
                null,
                0,
                true,
                false,
                false,
                false,
                true,
                true,
                AndroidApkSigningTool.CreatedBy,
                null)
        {
            mV1ContentDigestAlgorithm = digestAlgorithm;
            foreach (var v1SignerConfig in mV1SignerConfigs)
            {
                v1SignerConfig.signatureDigestAlgorithm = digestAlgorithm;
            }
        }

        private static List<SignerConfig> MapSignerConfigs(List<ApkSigner.SignerConfig> signerConfigs)
        {
            var engineSignerConfigs = new List<SignerConfig>(signerConfigs.Size());
            foreach (var signerConfig in signerConfigs)
            {
                engineSignerConfigs.Add(new SignerConfig.Builder(signerConfig.GetName(),
                    signerConfig.GetPrivateKey(),
                    signerConfig.GetCertificates(),
                    signerConfig.GetDeterministicDsaSigning()).Build());
            }
            return engineSignerConfigs;
        }
    }
}
