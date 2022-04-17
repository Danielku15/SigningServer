using SigningServer.Android.Collections;
using SigningServer.Android.Com.Android.Apksig;

namespace SigningServer.Android
{
    public class JarSignerEngine : DefaultApkSignerEngine
    {
        public JarSignerEngine(List<ApkSigner.SignerConfig> signerConfigs)
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